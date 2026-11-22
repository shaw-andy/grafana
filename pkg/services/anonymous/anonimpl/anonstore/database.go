package anonstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/search/model"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/sqlstore/migrator"
)

const cacheKeyPrefix = "anon-device"
const anonymousDeviceExpiration = 30 * 24 * time.Hour
const tableName = "anon_device"

// GET_LOCK names are server wide on MySQL, so the name is namespaced to Grafana.
const deviceLimitLockName = "grafana_anon_device_limit"
const deviceLimitLockTimeoutSeconds = 10

var ErrDeviceLimitReached = fmt.Errorf("device limit reached")
var errDeviceLimitLock = fmt.Errorf("could not acquire anonymous device limit lock")

type AnonDBStore struct {
	sqlStore    db.DB
	log         log.Logger
	deviceLimit int64
}

type Device struct {
	ID        int64     `json:"-" xorm:"pk autoincr 'id'" db:"id"`
	DeviceID  string    `json:"deviceId" xorm:"device_id" db:"device_id"`
	ClientIP  string    `json:"clientIp" xorm:"client_ip" db:"client_ip"`
	UserAgent string    `json:"userAgent" xorm:"user_agent" db:"user_agent"`
	CreatedAt time.Time `json:"createdAt" xorm:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updatedAt" xorm:"updated_at" db:"updated_at"`
}

type DeviceSearchHitDTO struct {
	DeviceID   string    `json:"deviceId" xorm:"device_id" db:"device_id"`
	ClientIP   string    `json:"clientIp" xorm:"client_ip" db:"client_ip"`
	UserAgent  string    `json:"userAgent" xorm:"user_agent" db:"user_agent"`
	CreatedAt  time.Time `json:"createdAt" xorm:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updatedAt" xorm:"updated_at" db:"updated_at"`
	LastSeenAt time.Time `json:"lastSeenAt"`
}

type SearchDeviceQueryResult struct {
	TotalCount int64                 `json:"totalCount"`
	Devices    []*DeviceSearchHitDTO `json:"devices"`
	Page       int                   `json:"page"`
	PerPage    int                   `json:"perPage"`
}
type SearchDeviceQuery struct {
	Query    string
	Page     int
	Limit    int
	From     time.Time
	To       time.Time
	SortOpts []model.SortOption
}

func (a *Device) CacheKey() string {
	return strings.Join([]string{cacheKeyPrefix, a.DeviceID}, ":")
}

type AnonStore interface {
	// ListDevices returns all devices that have been updated between the given times.
	ListDevices(ctx context.Context, from *time.Time, to *time.Time) ([]*Device, error)
	// CreateOrUpdateDevice creates or updates a device.
	CreateOrUpdateDevice(ctx context.Context, device *Device) error
	// CountDevices returns the number of devices that have been updated between the given times.
	CountDevices(ctx context.Context, from time.Time, to time.Time) (int64, error)
	// DeleteDevice deletes a device by its ID.
	DeleteDevice(ctx context.Context, deviceID string) error
	// DeleteDevicesOlderThan deletes all devices that have no been updated since the given time.
	DeleteDevicesOlderThan(ctx context.Context, olderThan time.Time) error
	// SearchDevices searches for devices within the 30 days active.
	SearchDevices(ctx context.Context, query *SearchDeviceQuery) (*SearchDeviceQueryResult, error)
}

func ProvideAnonDBStore(sqlStore db.DB, deviceLimit int64) *AnonDBStore {
	return &AnonDBStore{sqlStore: sqlStore, log: log.New("anonstore"), deviceLimit: deviceLimit}
}

func (s *AnonDBStore) ListDevices(ctx context.Context, from *time.Time, to *time.Time) ([]*Device, error) {
	devices := []*Device{}
	query := "SELECT * FROM anon_device"
	args := []any{}
	if from != nil && to != nil {
		query += " WHERE updated_at BETWEEN ? AND ?"
		args = append(args, from.UTC(), to.UTC())
	}

	err := s.sqlStore.WithDbSession(ctx, func(dbSession *sqlstore.DBSession) error {
		return dbSession.SQL(query, args...).Find(&devices)
	})

	return devices, err
}

// updateDevice updates a device if it exists and has been updated between the given times.
func updateDevice(dbSession *sqlstore.DBSession, device *Device) error {
	const query = `UPDATE anon_device SET
client_ip = ?,
user_agent = ?,
updated_at = ?
WHERE device_id = ? AND updated_at BETWEEN ? AND ?`

	result, err := dbSession.Exec(query, device.ClientIP, device.UserAgent, device.UpdatedAt.UTC(), device.DeviceID,
		device.UpdatedAt.UTC().Add(-anonymousDeviceExpiration), device.UpdatedAt.UTC().Add(time.Minute),
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrDeviceLimitReached
	}

	return nil
}

func (s *AnonDBStore) CreateOrUpdateDevice(ctx context.Context, device *Device) error {
	// If CreatedAt time is not set (i.e. it's zero), and we end up creating the device, use current time as creation time.
	// If database converts zero time to NULL, but CreatedAt is not nullable, this helps to fix that problem too.
	created := device.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}

	query, err := s.upsertDeviceQuery()
	if err != nil {
		return err
	}
	args := []any{query, device.DeviceID, device.ClientIP, device.UserAgent, created.UTC(), device.UpdatedAt.UTC()}

	if s.deviceLimit <= 0 {
		return s.sqlStore.WithDbSession(ctx, func(dbSession *sqlstore.DBSession) error {
			_, err := dbSession.Exec(args...)
			return err
		})
	}

	// The count and the write must be serialized across all callers (and Grafana instances);
	// otherwise concurrent callers each see a count below the limit and all insert.
	return s.sqlStore.WithTransactionalDbSession(ctx, func(dbSession *sqlstore.DBSession) error {
		unlock, err := s.lockDeviceLimit(ctx, dbSession)
		if err != nil {
			return err
		}
		defer unlock()

		now := time.Now().UTC()
		count, err := s.countDevicesForLimit(dbSession, now.Add(-anonymousDeviceExpiration), now.Add(time.Minute))
		if err != nil {
			return err
		}

		// if device limit is reached, only update devices
		if count >= s.deviceLimit {
			return updateDevice(dbSession, device)
		}

		_, err = dbSession.Exec(args...)
		return err
	})
}

// lockDeviceLimit takes a lock that serializes device-limit checks until the
// returned function is called or, where the lock is transaction scoped, until
// the transaction ends.
func (s *AnonDBStore) lockDeviceLimit(ctx context.Context, dbSession *sqlstore.DBSession) (func(), error) {
	switch s.sqlStore.GetDBType() {
	case migrator.Postgres:
		// Self-conflicting and also conflicts with any other INSERT/UPDATE/DELETE on the table.
		// Must run before any query in the transaction so that REPEATABLE READ/SERIALIZABLE
		// snapshots are taken after the lock is held.
		if _, err := dbSession.Exec("LOCK TABLE anon_device IN SHARE ROW EXCLUSIVE MODE"); err != nil {
			return nil, err
		}
		return func() {}, nil
	case migrator.MySQL:
		// GET_LOCK is session scoped and must be released before the pooled connection is
		// returned, so it is released before commit. countDevicesForLimit uses a locking read
		// on MySQL, which waits for the previous holder's uncommitted insert to commit.
		var acquired sql.NullInt64
		if _, err := dbSession.SQL("SELECT GET_LOCK(?, ?)", deviceLimitLockName, deviceLimitLockTimeoutSeconds).Get(&acquired); err != nil {
			return nil, err
		}
		if !acquired.Valid || acquired.Int64 != 1 {
			return nil, errDeviceLimitLock
		}
		return func() {
			var released sql.NullInt64
			if _, err := dbSession.SQL("SELECT RELEASE_LOCK(?)", deviceLimitLockName).Get(&released); err != nil {
				s.log.FromContext(ctx).Error("Failed to release anonymous device limit lock", "error", err)
			}
		}, nil
	case migrator.SQLite:
		// SQLite allows a single writer and fails the write of a transaction whose reads
		// are stale (SQLITE_BUSY), which makes the transaction retry with a fresh count.
		return func() {}, nil
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", s.sqlStore.GetDBType())
	}
}

func (s *AnonDBStore) countDevicesForLimit(dbSession *sqlstore.DBSession, from time.Time, to time.Time) (int64, error) {
	query := "SELECT COUNT(*) FROM anon_device WHERE updated_at BETWEEN ? AND ?"
	if s.sqlStore.GetDBType() == migrator.MySQL {
		query += " FOR UPDATE"
	}

	var count int64
	_, err := dbSession.SQL(query, from.UTC(), to.UTC()).Get(&count)
	return count, err
}

func (s *AnonDBStore) upsertDeviceQuery() (string, error) {
	var query string
	switch s.sqlStore.GetDBType() {
	case migrator.Postgres:
		query = `INSERT INTO anon_device (device_id, client_ip, user_agent, created_at, updated_at)
					VALUES ($1, $2, $3, $4, $5)
					ON CONFLICT (device_id) DO UPDATE SET
					client_ip = $2,
					user_agent = $3,
					updated_at = $5
					RETURNING id`
	case migrator.MySQL:
		query = `INSERT INTO anon_device (device_id, client_ip, user_agent, created_at, updated_at)
					VALUES (?, ?, ?, ?, ?)
					ON DUPLICATE KEY UPDATE
					client_ip = VALUES(client_ip),
					user_agent = VALUES(user_agent),
					updated_at = VALUES(updated_at)`
	case migrator.SQLite:
		query = `INSERT INTO anon_device (device_id, client_ip, user_agent, created_at, updated_at)
					VALUES (?, ?, ?, ?, ?)
					ON CONFLICT (device_id) DO UPDATE SET
					client_ip = excluded.client_ip,
					user_agent = excluded.user_agent,
					updated_at = excluded.updated_at`
	default:
		return "", fmt.Errorf("unsupported database driver: %s", s.sqlStore.GetDBType())
	}
	return query, nil
}

func (s *AnonDBStore) CountDevices(ctx context.Context, from time.Time, to time.Time) (int64, error) {
	var count int64
	err := s.sqlStore.WithDbSession(ctx, func(dbSession *sqlstore.DBSession) error {
		_, err := dbSession.SQL("SELECT COUNT(*) FROM anon_device WHERE updated_at BETWEEN ? AND ?", from.UTC(), to.UTC()).Get(&count)
		return err
	})

	return count, err
}

func (s *AnonDBStore) DeleteDevice(ctx context.Context, deviceID string) error {
	err := s.sqlStore.WithDbSession(ctx, func(dbSession *sqlstore.DBSession) error {
		_, err := dbSession.Exec("DELETE FROM anon_device WHERE device_id = ?", deviceID)
		return err
	})

	return err
}

// deleteOldDevices deletes all devices that have no been updated since the given time.
func (s *AnonDBStore) DeleteDevicesOlderThan(ctx context.Context, olderThan time.Time) error {
	err := s.sqlStore.WithDbSession(ctx, func(dbSession *sqlstore.DBSession) error {
		_, err := dbSession.Exec("DELETE FROM anon_device WHERE updated_at <= ?", olderThan.UTC())
		return err
	})

	return err
}

func (s *AnonDBStore) SearchDevices(ctx context.Context, query *SearchDeviceQuery) (*SearchDeviceQueryResult, error) {
	result := SearchDeviceQueryResult{
		Devices: make([]*DeviceSearchHitDTO, 0),
	}
	err := s.sqlStore.WithDbSession(ctx, func(dbSess *db.Session) error {
		if query.From.IsZero() && !query.To.IsZero() {
			return fmt.Errorf("from date must be set if to date is set")
		}
		if !query.From.IsZero() && query.To.IsZero() {
			return fmt.Errorf("to date must be set if from date is set")
		}

		// restricted only to last 30 days, if noting else specified
		if query.From.IsZero() && query.To.IsZero() {
			query.From = time.Now().Add(-anonymousDeviceExpiration)
			query.To = time.Now()
		}

		sess := dbSess.Table(tableName).Alias("d")

		if query.Limit > 0 {
			offset := query.Limit * (query.Page - 1)
			sess.Limit(query.Limit, offset)
		}
		sess.Cols("d.id", "d.device_id", "d.client_ip", "d.user_agent", "d.updated_at")

		if len(query.SortOpts) > 0 {
			for i := range query.SortOpts {
				for j := range query.SortOpts[i].Filter {
					sess.OrderBy(query.SortOpts[i].Filter[j].OrderBy())
				}
			}
		} else {
			sess.Asc("d.user_agent")
		}

		// add to query about from and to session
		sess.Where("d.updated_at BETWEEN ? AND ?", query.From.UTC(), query.To.UTC())

		if query.Query != "" {
			sql, param := s.sqlStore.GetDialect().LikeOperator("d.client_ip", true, strings.ReplaceAll(query.Query, "\\", ""), true)
			sess.Where(sql, param)
		}

		// get total
		devices, err := s.ListDevices(ctx, &query.From, &query.To)
		if err != nil {
			return err
		}
		// cast to int64
		result.TotalCount = int64(len(devices))
		if err := sess.Find(&result.Devices); err != nil {
			return err
		}
		result.Page = query.Page
		result.PerPage = query.Limit
		return nil
	})
	return &result, err
}
