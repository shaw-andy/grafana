import { css } from '@emotion/css';
import { type SyntheticEvent, useState } from 'react';

import { AppEvents, type GrafanaTheme2, PluginState } from '@grafana/data';
import { t } from '@grafana/i18n';
import { type BackendSrvRequest } from '@grafana/runtime';
import { TextDimensionMode } from '@grafana/schema';
import { Button, ConfirmModal, Spinner, useStyles2 } from '@grafana/ui';
import { ActionRequestDetails } from '@grafana/ui/internal';
import { appEvents } from 'app/core/app_events';
import { type DimensionContext } from 'app/features/dimensions/context';
import { ColorDimensionEditor } from 'app/features/dimensions/editors/ColorDimensionEditor';
import { TextDimensionEditor } from 'app/features/dimensions/editors/TextDimensionEditor';
import { APIEditor, type APIEditorConfig } from 'app/plugins/panel/canvas/editor/element/APIEditor';
import { type ButtonStyleConfig, ButtonStyleEditor } from 'app/plugins/panel/canvas/editor/element/ButtonStyleEditor';
import { getRequest, sendRequest } from 'app/plugins/panel/canvas/editor/element/utils';
import { HttpRequestMethod } from 'app/plugins/panel/canvas/panelcfg.gen';

import {
  type CanvasElementItem,
  type CanvasElementOptions,
  type CanvasElementProps,
  defaultLightTextColor,
} from '../element';
import { Align, type TextConfig, type TextData } from '../types';

interface ButtonData extends Omit<TextData, 'valign'> {
  api?: APIEditorConfig;
  style?: ButtonStyleConfig;
}

interface ButtonConfig extends Omit<TextConfig, 'valign'> {
  api?: APIEditorConfig;
  style?: ButtonStyleConfig;
}

export const defaultApiConfig: APIEditorConfig = {
  endpoint: '',
  method: HttpRequestMethod.POST,
  data: '{}',
  contentType: 'application/json',
  queryParams: [],
  headerParams: [],
  successMessage: 'API call was successful',
};

export const defaultStyleConfig: ButtonStyleConfig = {
  variant: 'primary',
};

interface PendingApiCall {
  request: BackendSrvRequest;
  successMessage?: string;
}

const stopPropagation = (event: SyntheticEvent) => event.stopPropagation();

const ButtonDisplay = ({ data }: CanvasElementProps<ButtonConfig, ButtonData>) => {
  const styles = useStyles2(getStyles, data);

  const [isLoading, setIsLoading] = useState(false);
  const [pendingCall, setPendingCall] = useState<PendingApiCall | undefined>();

  const updateLoadingStateCallback = (loading: boolean) => {
    setIsLoading(loading);
  };

  const onClick = () => {
    if (!data?.api?.endpoint) {
      return;
    }

    try {
      setPendingCall(Object.freeze({ request: getRequest(data.api), successMessage: data.api.successMessage }));
    } catch (error) {
      appEvents.emit(AppEvents.alertError, ['An error has occurred. Check console output for more details.']);
      console.error('API call error: ', error);
    }
  };

  const onConfirm = () => {
    if (!pendingCall) {
      return;
    }

    setPendingCall(undefined);
    setIsLoading(true);
    sendRequest(pendingCall.request, pendingCall.successMessage, updateLoadingStateCallback);
  };

  return (
    <>
      <Button type="submit" variant={data?.style?.variant} onClick={onClick} className={styles.button}>
        <span>
          {isLoading && <Spinner inline={true} className={styles.buttonSpinner} />}
          {data?.text}
        </span>
      </Button>
      {pendingCall && (
        // The modal is portaled, but its events still bubble to the canvas element's click and key handlers
        <span role="presentation" onClick={stopPropagation} onKeyDown={stopPropagation}>
          <ConfirmModal
            isOpen={true}
            title={t('canvas.button-item.confirm-title', 'Confirm API call')}
            body={t('canvas.button-item.confirm-body', 'Do you want to send this request?')}
            description={
              <ActionRequestDetails
                method={pendingCall.request.method ?? HttpRequestMethod.GET}
                url={pendingCall.request.url}
                body={typeof pendingCall.request.data === 'string' ? pendingCall.request.data : undefined}
              />
            }
            confirmText={t('canvas.button-item.confirm', 'Confirm')}
            confirmVariant="primary"
            onConfirm={onConfirm}
            onDismiss={() => setPendingCall(undefined)}
          />
        </span>
      )}
    </>
  );
};

const getStyles = (theme: GrafanaTheme2, data: ButtonData | undefined) => ({
  button: css({
    height: '100%',
    width: '100%',
    display: 'grid',

    '> span': {
      display: 'inline-grid',
      gridAutoFlow: 'column',
      textAlign: data?.align,
      fontSize: `${data?.size}px`,
      color: data?.color,
    },
  }),
  buttonSpinner: css({
    marginRight: theme.spacing(0.5),
  }),
});

export const buttonItem: CanvasElementItem<ButtonConfig, ButtonData> = {
  id: 'button',
  name: 'Button',
  description: 'Button',
  state: PluginState.beta,

  standardEditorConfig: {
    background: false,
  },

  display: ButtonDisplay,

  defaultSize: {
    width: 150,
    height: 45,
  },

  getNewOptions: (options) => ({
    ...options,
    config: {
      text: {
        mode: TextDimensionMode.Fixed,
        fixed: 'Button',
      },
      align: Align.Center,
      color: {
        fixed: defaultLightTextColor,
      },
      size: 14,
      api: defaultApiConfig,
      style: defaultStyleConfig,
    },
    background: {
      color: {
        fixed: 'transparent',
      },
    },
    placement: {
      width: options?.placement?.width ?? 32,
      height: options?.placement?.height ?? 78,
      top: options?.placement?.top ?? 100,
      left: options?.placement?.left ?? 100,
      rotation: options?.placement?.rotation ?? 0,
    },
  }),

  // Called when data changes
  prepareData: (dimensionContext: DimensionContext, elementOptions: CanvasElementOptions<ButtonConfig>) => {
    const buttonConfig = elementOptions.config;

    const getAPIConfig = () => {
      if (buttonConfig?.api) {
        buttonConfig.api = {
          ...buttonConfig.api,
          method: buttonConfig.api.method ?? defaultApiConfig.method,
          contentType: buttonConfig.api.contentType ?? defaultApiConfig.contentType,
        };
        return buttonConfig.api;
      }

      return undefined;
    };

    const data: ButtonData = {
      text: buttonConfig?.text ? dimensionContext.getText(buttonConfig.text).value() : '',
      align: buttonConfig?.align ?? Align.Center,
      size: buttonConfig?.size ?? 14,
      api: getAPIConfig(),
      style: buttonConfig?.style ?? defaultStyleConfig,
    };

    if (buttonConfig?.color) {
      data.color = dimensionContext.getColor(buttonConfig.color).value();
    }

    return data;
  },

  // Heatmap overlay options
  registerOptionsUI: (builder) => {
    const category = [t('canvas.button-item.category-button', 'Button')];
    builder
      .addCustomEditor({
        category,
        id: 'styleSelector',
        path: 'config.style',
        name: t('canvas.button-item.name-style', 'Style'),
        editor: ButtonStyleEditor,
      })
      .addCustomEditor({
        category,
        id: 'textSelector',
        path: 'config.text',
        name: t('canvas.button-item.name-text', 'Text'),
        editor: TextDimensionEditor,
      })
      .addCustomEditor({
        category,
        id: 'config.color',
        path: 'config.color',
        name: t('canvas.button-item.name-text-color', 'Text color'),
        editor: ColorDimensionEditor,
        settings: {},
        defaultValue: {},
      })
      .addRadio({
        category,
        path: 'config.align',
        name: t('canvas.button-item.name-align-text', 'Align text'),
        settings: {
          options: [
            { value: Align.Left, label: t('canvas.button-item.label.left', 'Left') },
            { value: Align.Center, label: t('canvas.button-item.label.center', 'Center') },
            { value: Align.Right, label: t('canvas.button-item.label.right', 'Right') },
          ],
        },
        defaultValue: Align.Left,
      })
      .addNumberInput({
        category,
        path: 'config.size',
        name: t('canvas.button-item.name-text-size', 'Text size'),
        settings: {
          placeholder: t('canvas.button-item.placeholder.auto', 'Auto'),
        },
      })
      .addCustomEditor({
        category,
        id: 'apiSelector',
        path: 'config.api',
        name: t('canvas.button-item.name-api', 'API'),
        editor: APIEditor,
      });
  },
};
