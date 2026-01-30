use cipherrun::api::models::response::ProgressMessage;

#[test]
fn test_progress_message_builders() {
    let msg = ProgressMessage::new("scan-1", 42, "phase");
    assert_eq!(msg.msg_type, "progress");
    assert_eq!(msg.scan_id, "scan-1");
    assert_eq!(msg.progress, 42);

    let done = ProgressMessage::completed("scan-2");
    assert_eq!(done.msg_type, "completed");
    assert_eq!(done.scan_id, "scan-2");
    assert_eq!(done.progress, 100);

    let failed = ProgressMessage::failed("scan-3", "error");
    assert_eq!(failed.msg_type, "failed");
    assert_eq!(failed.scan_id, "scan-3");
    assert_eq!(failed.progress, 0);
    assert_eq!(failed.details.as_deref(), Some("error"));
}
