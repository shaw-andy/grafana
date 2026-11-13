import { useState } from 'react';

import { type ActionModel, type Field, type ActionVariableInput, type PreparedActionRequest } from '@grafana/data';
import { t } from '@grafana/i18n';

import { useTheme2 } from '../../themes/ThemeContext';
import { Button, type ButtonProps } from '../Button/Button';
import { ConfirmModal } from '../ConfirmModal/ConfirmModal';

import { ActionRequestDetails } from './ActionRequestDetails';
import { VariablesInputModal } from './VariablesInputModal';

type ActionButtonProps = Omit<ButtonProps, 'children'> & {
  action: ActionModel<Field>;
};

/**
 * @internal
 */
export function ActionButton({ action, ...buttonProps }: ActionButtonProps) {
  const theme = useTheme2();
  const backgroundColor = action.style.backgroundColor || theme.colors.secondary.main;
  const textColor = theme.colors.getContrastText(backgroundColor);

  const [showConfirm, setShowConfirm] = useState(false);
  const [preparedRequest, setPreparedRequest] = useState<PreparedActionRequest | undefined>();

  // Action variables
  const [showVarsModal, setShowVarsModal] = useState(false);
  const [actionVars, setActionVars] = useState<ActionVariableInput>({});

  const actionHasVariables = action.variables && action.variables.length > 0;

  const openConfirm = () => {
    if (action.prepare) {
      const prepared = action.prepare(actionVars);
      if (!prepared) {
        return;
      }
      setPreparedRequest(prepared);
    }
    setShowConfirm(true);
  };

  const closeConfirm = () => {
    setShowConfirm(false);
    setPreparedRequest(undefined);
  };

  const onClick = () => {
    if (actionHasVariables) {
      setShowVarsModal(true);
    } else {
      openConfirm();
    }
  };

  return (
    <>
      <Button
        variant="primary"
        size="sm"
        onClick={onClick}
        {...buttonProps}
        style={{ width: 'fit-content', backgroundColor, color: textColor }}
      >
        {action.title}
      </Button>

      {actionHasVariables && showVarsModal && (
        <VariablesInputModal
          onDismiss={() => setShowVarsModal(false)}
          action={action}
          onShowConfirm={openConfirm}
          variables={actionVars}
          setVariables={setActionVars}
        />
      )}

      {showConfirm && (
        <ConfirmModal
          isOpen={true}
          title={t('grafana-ui.action-editor.button.confirm-action', 'Confirm action')}
          body={action.confirmation(actionVars)}
          description={
            preparedRequest && (
              <ActionRequestDetails
                method={preparedRequest.method}
                url={preparedRequest.url}
                body={preparedRequest.body}
              />
            )
          }
          confirmText={t('grafana-ui.action-editor.button.confirm', 'Confirm')}
          confirmVariant="primary"
          onConfirm={() => {
            closeConfirm();
            if (preparedRequest) {
              preparedRequest.execute();
            } else {
              action.onClick(new MouseEvent('click'), null, actionVars);
            }
          }}
          onDismiss={closeConfirm}
        />
      )}
    </>
  );
}
