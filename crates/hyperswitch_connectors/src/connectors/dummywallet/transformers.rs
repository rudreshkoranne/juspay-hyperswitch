use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::RouterData as _,
};
use common_enums::enums;
use common_utils::pii::Email;
use common_utils::request::Method;
use common_utils::types::MinorUnit;
use hyperswitch_domain_models::payment_method_data::WalletData;
use hyperswitch_domain_models::router_data::PaymentMethodToken;
use hyperswitch_domain_models::router_request_types::ResponseId;
use hyperswitch_domain_models::router_response_types::RedirectForm;
use hyperswitch_domain_models::types;
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, RouterData},
    router_flow_types::refunds::{Execute, RSync},
    //router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::errors;
use masking::Secret;
use serde::{Deserialize, Serialize};

//TODO: Fill the struct with respective fields
pub struct DummyWalletRouterData<T> {
    pub amount: MinorUnit, // The type of amount that a connector accepts, for example, String, i64, f64, etc.
    pub router_data: T,
}

impl<T> From<(MinorUnit, T)> for DummyWalletRouterData<T> {
    fn from((amount, item): (MinorUnit, T)) -> Self {
        Self {
            amount,
            router_data: item,
        }
    }
}

//TODO: Fill the struct with respective fields
#[derive(Default, Debug, Serialize, PartialEq)]
pub struct DummyWalletPaymentsRequest {
    pub amount: MinorUnit,
    pub currency: String,
    pub payment_method: DummyWalletPaymentMethod,
    pub customer: Option<DummyWalletCustomer>,
    pub reference_id: String,
    pub description: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Default, PartialEq)]
pub struct DummyWalletPaymentMethod {
    pub wallet_type: String,
    pub wallet_token: Option<Secret<String>>,
}

#[derive(Debug, Serialize, Default, PartialEq)]
pub struct DummyWalletCustomer {
    pub id: Option<common_utils::id_type::CustomerId>,
    pub email: Option<Email>,
    pub phone: Option<hyperswitch_domain_models::address::Address>,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct DummywalletCard {
    number: cards::CardNumber,
    expiry_month: Secret<String>,
    expiry_year: Secret<String>,
    cvc: Secret<String>,
    complete: bool,
}

impl TryFrom<&DummyWalletRouterData<&types::PaymentsAuthorizeRouterData>>
    for DummyWalletPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &DummyWalletRouterData<&types::PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        let payment_method = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Wallet(wallet_data) => {
                let wallet_type = match wallet_data {
                    WalletData::PaypalRedirect(_) => "paypal",
                    WalletData::GooglePay(_) => "google_pay",
                    WalletData::ApplePay(_) => "apple_pay",
                    WalletData::AliPayQr(_) => "alipay",
                    WalletData::WeChatPayQr(_) => "wechat_pay",
                    _ => "generic_wallet",
                };

                DummyWalletPaymentMethod {
                    wallet_type: wallet_type.to_string(),
                    wallet_token: item.router_data.get_payment_method_token().ok().and_then(
                        |token| match token {
                            PaymentMethodToken::Token(t) => Some(t),
                            _ => None,
                        },
                    ),
                }
            }
            _ => {
                return Err(errors::ConnectorError::NotSupported {
                    message: "Payment method not supported".to_string(),
                    connector: "DummyWallet",
                }
                .into())
            }
        };

        Ok(Self {
            amount: item.amount,
            currency: item.router_data.request.currency.to_string(),
            payment_method,
            customer: Some(DummyWalletCustomer {
                id: item.router_data.customer_id.clone(),
                email: item.router_data.request.email.clone(),
                phone: item.router_data.get_optional_billing().cloned(),
            }),
            reference_id: item.router_data.connector_request_reference_id.clone(),
            description: None, //item.router_data.request.description.clone(),
            metadata: item.router_data.request.metadata.clone(),
        })
    }
}

//TODO: Fill the struct with respective fields
// Auth Struct
pub struct DummyWalletAuthType {
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for DummyWalletAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}
// PaymentsResponse
//TODO: Append the remaining status flags
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DummywalletPaymentStatus {
    Succeeded,
    Failed,
    #[default]
    Processing,
}

impl From<DummywalletPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: DummywalletPaymentStatus) -> Self {
        match item {
            DummywalletPaymentStatus::Succeeded => Self::Charged,
            DummywalletPaymentStatus::Failed => Self::Failure,
            DummywalletPaymentStatus::Processing => Self::Authorizing,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DummyWalletPaymentStatus {
    Pending,
    Authorized,
    Captured,
    Failed,
    Cancelled,
    RequiresAction,
}
//TODO: Fill the struct with respective fields
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DummyWalletPaymentsResponse {
    pub id: String,
    pub status: DummyWalletPaymentStatus,
    pub amount: MinorUnit,
    pub currency: String,
    pub reference_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub failure_reason: Option<String>,
    pub redirect_url: Option<String>,
}

impl From<DummyWalletPaymentStatus> for enums::AttemptStatus {
    fn from(item: DummyWalletPaymentStatus) -> Self {
        match item {
            DummyWalletPaymentStatus::Pending => Self::Pending,
            DummyWalletPaymentStatus::Authorized => Self::Authorized,
            DummyWalletPaymentStatus::Captured => Self::Charged,
            DummyWalletPaymentStatus::Failed => Self::Failure,
            DummyWalletPaymentStatus::Cancelled => Self::Voided,
            DummyWalletPaymentStatus::RequiresAction => Self::AuthenticationPending,
        }
    }
}

impl<F, T> TryFrom<ResponseRouterData<F, DummyWalletPaymentsResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<F, DummyWalletPaymentsResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let status = enums::AttemptStatus::from(item.response.status.clone());

        let redirection_data = Box::new(item.response.redirect_url.as_ref().and_then(|url_str| {
            url::Url::parse(url_str)
                .ok()
                .map(|url| RedirectForm::from((url, Method::Get)))
        }));

        Ok(Self {
            status,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data,
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.reference_id),
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

//TODO: Fill the struct with respective fields
// REFUND :
// Type definition for RefundRequest
#[derive(Default, Debug, Serialize)]
pub struct DummywalletRefundRequest {
    pub amount: MinorUnit,
}

impl<F> TryFrom<&DummyWalletRouterData<&RefundsRouterData<F>>> for DummywalletRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &DummyWalletRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.amount.to_owned(),
        })
    }
}

// Type definition for Refund Response

#[allow(dead_code)]
#[derive(Debug, Copy, Serialize, Default, Deserialize, Clone)]
pub enum RefundStatus {
    Succeeded,
    Failed,
    #[default]
    Processing,
}

impl From<RefundStatus> for enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Succeeded => Self::Success,
            RefundStatus::Failed => Self::Failure,
            RefundStatus::Processing => Self::Pending,
            //TODO: Review mapping
        }
    }
}

//TODO: Fill the struct with respective fields
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    id: String,
    status: RefundStatus,
}

impl TryFrom<RefundsResponseRouterData<Execute, RefundResponse>> for RefundsRouterData<Execute> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<Execute, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.status),
            }),
            ..item.data
        })
    }
}

impl TryFrom<RefundsResponseRouterData<RSync, RefundResponse>> for RefundsRouterData<RSync> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<RSync, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.status),
            }),
            ..item.data
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DummyWalletErrorResponse {
    pub error: DummyWalletError,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DummyWalletError {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}
// Remove this local WalletData enum definition, as it conflicts with the imported one.   GenericWallet(String),
