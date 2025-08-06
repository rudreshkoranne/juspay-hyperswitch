use std::fmt::Debug;

use crate::{constants::headers, utils};
use common_enums::enums;
use common_utils::{
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    request::{Request, RequestContent},
};
use error_stack::report;
use hyperswitch_interfaces::webhooks;
use error_stack::ResultExt;
use hyperswitch_domain_models::router_data::ConnectorAuthType;
use hyperswitch_domain_models::router_flow_types::Authorize;
use hyperswitch_domain_models::router_flow_types::PaymentMethodToken;
use hyperswitch_domain_models::router_flow_types::Session;
use hyperswitch_domain_models::router_request_types::PaymentMethodTokenizationData;
use hyperswitch_domain_models::router_request_types::PaymentsSessionData;
use hyperswitch_domain_models::{
    router_data::{ErrorResponse, RouterData},
    router_response_types::PaymentsResponseData,
    types::PaymentsAuthorizeRouterData,
};
use hyperswitch_interfaces::{
    api::{self, ConnectorCommon, ConnectorCommonExt, ConnectorIntegration, ConnectorValidation},
    configs::Connectors,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::{self, Response},
};
use masking::{Mask, PeekInterface};

pub mod transformers;

use transformers as dummywallet;

#[derive(Debug, Clone)]
pub struct Dummywallet;

impl Dummywallet {
    // Provides a static instance similar to other connectors like `Stripe`
    pub const fn new() -> &'static Self {
        &Self {}
    }
}

// Type alias so that both `DummyWallet` and `Dummywallet` refer to the same connector struct.
// This satisfies tests which instantiate `DummyWallet::new()`.
pub type DummyWallet = Dummywallet;

// Implement ConnectorCommonExt for Dummywallet to provide build_headers
impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Dummywallet
where
    Self: ConnectorIntegration<Flow, Request, Response>,
{
    fn build_headers(
        &self,
        req: &RouterData<Flow, Request, Response>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.get_content_type().to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }
}

impl api::PaymentSession for DummyWallet {}
impl api::PaymentToken for DummyWallet {}
impl api::Payment for DummyWallet {}
impl api::MandateSetup for DummyWallet {}
impl api::PaymentAuthorize for DummyWallet {}
impl api::PaymentSync for DummyWallet {}
impl api::PaymentCapture for DummyWallet {}
impl api::PaymentVoid for DummyWallet {}

impl api::Refund for DummyWallet {}
impl api::RefundExecute for DummyWallet {}
impl api::RefundSync for DummyWallet {}

// Implement ConnectorIntegration for Execute refund flow
impl
    ConnectorIntegration<
        hyperswitch_domain_models::router_flow_types::refunds::Execute,
        hyperswitch_domain_models::router_request_types::RefundsData,
        hyperswitch_domain_models::router_response_types::RefundsResponseData,
    > for Dummywallet
{
    fn get_headers(
        &self,
        _req: &hyperswitch_domain_models::router_data::RouterData<
            hyperswitch_domain_models::router_flow_types::refunds::Execute,
            hyperswitch_domain_models::router_request_types::RefundsData,
            hyperswitch_domain_models::router_response_types::RefundsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![])
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &hyperswitch_domain_models::router_data::RouterData<
            hyperswitch_domain_models::router_flow_types::refunds::Execute,
            hyperswitch_domain_models::router_request_types::RefundsData,
            hyperswitch_domain_models::router_response_types::RefundsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok("".to_string())
    }

    fn get_request_body(
        &self,
        _req: &hyperswitch_domain_models::router_data::RouterData<
            hyperswitch_domain_models::router_flow_types::refunds::Execute,
            hyperswitch_domain_models::router_request_types::RefundsData,
            hyperswitch_domain_models::router_response_types::RefundsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        Ok(RequestContent::Json(Box::new(serde_json::json!({}))))
    }
}

// Implement ConnectorIntegration for RSync refund flow
impl
    ConnectorIntegration<
        hyperswitch_domain_models::router_flow_types::refunds::RSync,
        hyperswitch_domain_models::router_request_types::RefundsData,
        hyperswitch_domain_models::router_response_types::RefundsResponseData,
    > for Dummywallet
{
    fn get_headers(
        &self,
        _req: &hyperswitch_domain_models::router_data::RouterData<
            hyperswitch_domain_models::router_flow_types::refunds::RSync,
            hyperswitch_domain_models::router_request_types::RefundsData,
            hyperswitch_domain_models::router_response_types::RefundsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![])
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &hyperswitch_domain_models::router_data::RouterData<
            hyperswitch_domain_models::router_flow_types::refunds::RSync,
            hyperswitch_domain_models::router_request_types::RefundsData,
            hyperswitch_domain_models::router_response_types::RefundsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok("".to_string())
    }

    fn get_request_body(
        &self,
        _req: &hyperswitch_domain_models::router_data::RouterData<
            hyperswitch_domain_models::router_flow_types::refunds::RSync,
            hyperswitch_domain_models::router_request_types::RefundsData,
            hyperswitch_domain_models::router_response_types::RefundsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        Ok(RequestContent::Json(Box::new(serde_json::json!({}))))
    }
}
impl api::ConnectorAccessToken for DummyWallet {}

// Implement ConnectorIntegration for AccessTokenAuth flow
impl
    hyperswitch_interfaces::api::ConnectorIntegration<
        hyperswitch_domain_models::router_flow_types::access_token_auth::AccessTokenAuth,
        hyperswitch_domain_models::router_request_types::AccessTokenRequestData,
        hyperswitch_domain_models::router_data::AccessToken,
    > for Dummywallet
{
    fn get_headers(
        &self,
        _req: &hyperswitch_domain_models::router_data::RouterData<
            hyperswitch_domain_models::router_flow_types::access_token_auth::AccessTokenAuth,
            hyperswitch_domain_models::router_request_types::AccessTokenRequestData,
            hyperswitch_domain_models::router_data::AccessToken,
        >,
        _connectors: &hyperswitch_interfaces::configs::Connectors,
    ) -> common_utils::errors::CustomResult<
        Vec<(String, masking::Maskable<String>)>,
        hyperswitch_interfaces::errors::ConnectorError,
    > {
        Ok(vec![])
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &hyperswitch_domain_models::router_data::RouterData<
            hyperswitch_domain_models::router_flow_types::access_token_auth::AccessTokenAuth,
            hyperswitch_domain_models::router_request_types::AccessTokenRequestData,
            hyperswitch_domain_models::router_data::AccessToken,
        >,
        _connectors: &hyperswitch_interfaces::configs::Connectors,
    ) -> common_utils::errors::CustomResult<String, hyperswitch_interfaces::errors::ConnectorError>
    {
        Ok("".to_string())
    }

    fn get_request_body(
        &self,
        _req: &hyperswitch_domain_models::router_data::RouterData<
            hyperswitch_domain_models::router_flow_types::access_token_auth::AccessTokenAuth,
            hyperswitch_domain_models::router_request_types::AccessTokenRequestData,
            hyperswitch_domain_models::router_data::AccessToken,
        >,
        _connectors: &hyperswitch_interfaces::configs::Connectors,
    ) -> common_utils::errors::CustomResult<
        common_utils::request::RequestContent,
        hyperswitch_interfaces::errors::ConnectorError,
    > {
        Ok(common_utils::request::RequestContent::Json(Box::new(
            serde_json::json!({}),
        )))
    }
}

// Implement missing ConnectorIntegration traits for Dummywallet

// SetupMandate
impl
    ConnectorIntegration<
        hyperswitch_domain_models::router_flow_types::SetupMandate,
        hyperswitch_domain_models::router_request_types::SetupMandateRequestData,
        PaymentsResponseData,
    > for Dummywallet
{
    fn get_headers(
        &self,
        _req: &RouterData<
            hyperswitch_domain_models::router_flow_types::SetupMandate,
            hyperswitch_domain_models::router_request_types::SetupMandateRequestData,
            PaymentsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![])
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &RouterData<
            hyperswitch_domain_models::router_flow_types::SetupMandate,
            hyperswitch_domain_models::router_request_types::SetupMandateRequestData,
            PaymentsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok("".to_string())
    }

    fn get_request_body(
        &self,
        _req: &RouterData<
            hyperswitch_domain_models::router_flow_types::SetupMandate,
            hyperswitch_domain_models::router_request_types::SetupMandateRequestData,
            PaymentsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        Ok(RequestContent::Json(Box::new(serde_json::json!({}))))
    }
}

// Void
impl
    ConnectorIntegration<
        hyperswitch_domain_models::router_flow_types::Void,
        hyperswitch_domain_models::router_request_types::PaymentsCancelData,
        PaymentsResponseData,
    > for Dummywallet
{
    fn get_headers(
        &self,
        _req: &RouterData<
            hyperswitch_domain_models::router_flow_types::Void,
            hyperswitch_domain_models::router_request_types::PaymentsCancelData,
            PaymentsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![])
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &RouterData<
            hyperswitch_domain_models::router_flow_types::Void,
            hyperswitch_domain_models::router_request_types::PaymentsCancelData,
            PaymentsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok("".to_string())
    }

    fn get_request_body(
        &self,
        _req: &RouterData<
            hyperswitch_domain_models::router_flow_types::Void,
            hyperswitch_domain_models::router_request_types::PaymentsCancelData,
            PaymentsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        Ok(RequestContent::Json(Box::new(serde_json::json!({}))))
    }
}

// Capture
impl
    ConnectorIntegration<
        hyperswitch_domain_models::router_flow_types::Capture,
        hyperswitch_domain_models::router_request_types::PaymentsCaptureData,
        PaymentsResponseData,
    > for Dummywallet
{
    fn get_headers(
        &self,
        _req: &RouterData<
            hyperswitch_domain_models::router_flow_types::Capture,
            hyperswitch_domain_models::router_request_types::PaymentsCaptureData,
            PaymentsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![])
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &RouterData<
            hyperswitch_domain_models::router_flow_types::Capture,
            hyperswitch_domain_models::router_request_types::PaymentsCaptureData,
            PaymentsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok("".to_string())
    }

    fn get_request_body(
        &self,
        _req: &RouterData<
            hyperswitch_domain_models::router_flow_types::Capture,
            hyperswitch_domain_models::router_request_types::PaymentsCaptureData,
            PaymentsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        Ok(RequestContent::Json(Box::new(serde_json::json!({}))))
    }
}

// PSync
impl
    ConnectorIntegration<
        hyperswitch_domain_models::router_flow_types::PSync,
        hyperswitch_domain_models::router_request_types::PaymentsSyncData,
        PaymentsResponseData,
    > for Dummywallet
{
    fn get_headers(
        &self,
        _req: &RouterData<
            hyperswitch_domain_models::router_flow_types::PSync,
            hyperswitch_domain_models::router_request_types::PaymentsSyncData,
            PaymentsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![])
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &RouterData<
            hyperswitch_domain_models::router_flow_types::PSync,
            hyperswitch_domain_models::router_request_types::PaymentsSyncData,
            PaymentsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok("".to_string())
    }

    fn get_request_body(
        &self,
        _req: &RouterData<
            hyperswitch_domain_models::router_flow_types::PSync,
            hyperswitch_domain_models::router_request_types::PaymentsSyncData,
            PaymentsResponseData,
        >,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        Ok(RequestContent::Json(Box::new(serde_json::json!({}))))
    }
}

impl ConnectorCommon for Dummywallet {
    fn id(&self) -> &'static str {
        "dummywallet"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.dummywallet.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        let auth = dummywallet::DummyWalletAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", auth.api_key.peek()).into_masked(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: dummywallet::DummyWalletErrorResponse = res
            .response
            .parse_struct("DummyWalletErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_error_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.error.code,
            message: response.error.message,
            reason: response.error.details.map(|d| d.to_string()),
            attempt_status: None,
            connector_transaction_id: None,
            network_decline_code: None,
            network_advice_code: None,
            network_error_message: None,
        })
    }
}

impl ConnectorValidation for Dummywallet {
    fn validate_connector_against_payment_request(
        &self,
        capture_method: Option<enums::CaptureMethod>,
        payment_method: enums::PaymentMethod,
        _pmt: Option<enums::PaymentMethodType>,
    ) -> CustomResult<(), errors::ConnectorError> {
        let capture_method = capture_method.unwrap_or_default();
        match capture_method {
            enums::CaptureMethod::Automatic | enums::CaptureMethod::Manual => Ok(()),
            enums::CaptureMethod::ManualMultiple
            | enums::CaptureMethod::Scheduled
            | enums::CaptureMethod::SequentialAutomatic => Err(
                utils::construct_not_supported_error_report(capture_method, self.id()),
            ),
        }?;

        match payment_method {
            enums::PaymentMethod::Wallet => Ok(()),
            _ => Err(utils::construct_not_supported_error_report(
                capture_method,
                self.id(),
            )),
        }
    }
}

impl
    ConnectorIntegration<
        Authorize,
        hyperswitch_domain_models::router_request_types::PaymentsAuthorizeData,
        PaymentsResponseData,
    > for Dummywallet
{
    fn get_headers(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}/payments", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount = utils::convert_amount(
            &common_utils::types::MinorUnitForConnector,
            req.request.minor_amount,
            req.request.currency,
        )?;
        let connector_router_data = dummywallet::DummyWalletRouterData::from((amount, req));
        let connector_req =
            dummywallet::DummyWalletPaymentsRequest::try_from(&connector_router_data)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }
}

// Payment Method Token Integration
impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Dummywallet
{
    fn get_headers(
        &self,
        req: &RouterData<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &RouterData<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}/tokenize", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        _req: &RouterData<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        // For dummy implementation, return empty JSON
        Ok(RequestContent::Json(Box::new(serde_json::json!({}))))
    }

    fn build_request(
        &self,
        _req: &RouterData<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        // For dummy implementation, return None to skip actual request
        Ok(None)
    }

    fn handle_response(
        &self,
        data: &RouterData<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<
        RouterData<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        // For dummy implementation, return success with dummy token
        let response = PaymentsResponseData::TokenizationResponse {
            token: "dummy_token_12345".to_string(),
        };

        Ok(RouterData {
            response: Ok(response),
            ..data.clone()
        })
    }
}
// Payment Session Integration
impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Dummywallet {
    fn get_headers(
        &self,
        req: &RouterData<Session, PaymentsSessionData, PaymentsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &RouterData<Session, PaymentsSessionData, PaymentsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}/sessions", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        _req: &RouterData<Session, PaymentsSessionData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        // For dummy implementation, return empty JSON
        Ok(RequestContent::Json(Box::new(serde_json::json!({}))))
    }

    fn build_request(  
        &self,  
        _req: &RouterData<Session, PaymentsSessionData, PaymentsResponseData>,  
        _connectors: &Connectors,  
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {  
        // For dummy implementation, return None to skip actual request  
        Ok(None)  
    }

    fn handle_response(
        &self,
        data: &RouterData<Session, PaymentsSessionData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        _res: Response,
    ) -> CustomResult<
        RouterData<Session, PaymentsSessionData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        // For dummy implementation, return success with dummy session
        let response = PaymentsResponseData::SessionResponse {
            session_token: api_models::payments::SessionToken::NoSessionTokenReceived,
        };

        Ok(RouterData {
            response: Ok(response),
            ..data.clone()
        })
    }
}
#[async_trait::async_trait]  
impl webhooks::IncomingWebhook for Dummywallet {  
    fn get_webhook_object_reference_id(  
        &self,  
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,  
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {  
        Err(report!(errors::ConnectorError::WebhooksNotImplemented))  
    }  
  
    fn get_webhook_event_type(  
        &self,  
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,  
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {  
        Err(report!(errors::ConnectorError::WebhooksNotImplemented))  
    }  
  
    fn get_webhook_resource_object(  
        &self,  
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,  
    ) -> CustomResult<Box<dyn masking::ErasedMaskSerialize>, errors::ConnectorError> {  
        Err(report!(errors::ConnectorError::WebhooksNotImplemented))  
    }  
}

use hyperswitch_domain_models::router_response_types::ConnectorInfo;
use hyperswitch_domain_models::router_response_types::SupportedPaymentMethods;
use std::sync::LazyLock;

// Static variables for connector specifications
static DUMMYWALLET_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(SupportedPaymentMethods::new);

static DUMMYWALLET_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Dummywallet",
    description: "Dummywallet connector",
    connector_type: enums::PaymentConnectorCategory::PaymentGateway,
};

static DUMMYWALLET_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 0] = [];

impl api::ConnectorSpecifications for Dummywallet {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&DUMMYWALLET_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*DUMMYWALLET_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        Some(&DUMMYWALLET_SUPPORTED_WEBHOOK_FLOWS)
    }
}
