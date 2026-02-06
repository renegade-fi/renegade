//! SQS message submission logic

use aws_sdk_sqs::Client as SqsClient;
use eyre::{Result, eyre};
use task_driver::utils::indexer_client::Message;
use tracing::info;

/// Submits a message to the SQS queue
pub async fn submit_message(
    sqs_client: &SqsClient,
    queue_url: &str,
    message: Message,
) -> Result<()> {
    let message_body =
        serde_json::to_string(&message).map_err(|e| eyre!("failed to serialize message: {e}"))?;

    let mut request = sqs_client.send_message().queue_url(queue_url).message_body(message_body);

    // Set the message group ID for FIFO queue ordering
    let group_id = match &message {
        Message::RegisterMasterViewSeed(msg) => msg.account_id.to_string(),
        Message::UpdatePublicIntentMetadata(msg) => msg.order_id.to_string(),
    };
    request = request.message_group_id(group_id);

    // No deduplication ID - using content-based deduplication
    request.send().await.map_err(|e| eyre!("failed to send SQS message: {e}"))?;

    info!("Successfully submitted message to SQS queue");
    Ok(())
}
