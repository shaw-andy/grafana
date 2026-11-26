package v2

import (
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidateElementReferences rejects layouts that place the same element more than once.
// Conversion to v1 emits one full panel per layout item, so repeated references would let a
// small stored dashboard expand into an arbitrarily large converted one.
// All layout branches are walked, including ones a converter might ignore, so a reference
// cannot be hidden in a branch that is not normally populated.
func ValidateElementReferences(spec *DashboardSpec) field.ErrorList {
	w := elementReferenceWalker{seen: make(map[string]struct{}, len(spec.Elements))}
	l := &spec.Layout
	w.walkLayout(field.NewPath("spec", "layout"), l.GridLayoutKind, l.RowsLayoutKind, l.AutoGridLayoutKind, l.TabsLayoutKind)
	if w.err != nil {
		return field.ErrorList{w.err}
	}
	return nil
}

type elementReferenceWalker struct {
	seen map[string]struct{}
	err  *field.Error
}

func (w *elementReferenceWalker) walkLayout(path *field.Path, grid *DashboardGridLayoutKind, rows *DashboardRowsLayoutKind, auto *DashboardAutoGridLayoutKind, tabs *DashboardTabsLayoutKind) {
	if grid != nil {
		itemsPath := path.Child("spec", "items")
		for i := range grid.Spec.Items {
			if !w.reference(itemsPath.Index(i).Child("spec", "element", "name"), grid.Spec.Items[i].Spec.Element.Name) {
				return
			}
		}
	}
	if auto != nil {
		itemsPath := path.Child("spec", "items")
		for i := range auto.Spec.Items {
			if !w.reference(itemsPath.Index(i).Child("spec", "element", "name"), auto.Spec.Items[i].Spec.Element.Name) {
				return
			}
		}
	}
	if rows != nil {
		rowsPath := path.Child("spec", "rows")
		for i := range rows.Spec.Rows {
			l := &rows.Spec.Rows[i].Spec.Layout
			w.walkLayout(rowsPath.Index(i).Child("spec", "layout"), l.GridLayoutKind, l.RowsLayoutKind, l.AutoGridLayoutKind, l.TabsLayoutKind)
			if w.err != nil {
				return
			}
		}
	}
	if tabs != nil {
		tabsPath := path.Child("spec", "tabs")
		for i := range tabs.Spec.Tabs {
			l := &tabs.Spec.Tabs[i].Spec.Layout
			w.walkLayout(tabsPath.Index(i).Child("spec", "layout"), l.GridLayoutKind, l.RowsLayoutKind, l.AutoGridLayoutKind, l.TabsLayoutKind)
			if w.err != nil {
				return
			}
		}
	}
}

func (w *elementReferenceWalker) reference(path *field.Path, name string) bool {
	if _, ok := w.seen[name]; ok {
		w.err = field.Duplicate(path, name)
		return false
	}
	w.seen[name] = struct{}{}
	return true
}
