//! dump_messages — a non-interactive dump of every folder, message, recipient
//! and attachment in a PST, for the differential tests of pypst rows P08/P09.
//!
//! This file is part of pypst (MIT). It uses the `outlook-pst` crate
//! (https://github.com/microsoft/outlook-pst-rs, MIT, Copyright (c) Microsoft
//! Corporation) as a path dependency and is modelled on that crate's
//! `browse_pst` example, whose only message-level view is an interactive TUI.
//! It is not part of, and is not endorsed by, the upstream project.
//!
//! Usage: dump_messages <pst>
//!
//! Output is deterministic: a pre-order walk from `NID_ROOT_FOLDER` (so the
//! IPM subtree, the wastebasket and the search folders are all visible), each
//! folder's contents-table rows in row-matrix order, each message's recipient
//! and attachment rows in row-matrix order, and an embedded message (attach
//! method 5) printed one level further in. Values are printed with the same
//! `Debug` formatting the upstream examples use (`read_ipm_subtree`), so the
//! parsers in tests/golden_parsers.py apply; a time is upstream's
//! `Time(<i64 FILETIME>)`, a value not a date (and not hex: capture_oracle.py
//! scrubs 12–16-digit hex runs as pointer addresses). Body contents are never printed:
//! a body is summarised as its raw byte length and CRC-32 so P09 can check
//! content without the golden containing it.
//!
//! Two kinds of failure, deliberately kept apart. An accessor that fails
//! (`display_name()` on a root folder whose name is `PtypNull`, say) prints
//! `Error: <Debug>` *in place of the value* and is not counted: it is a fact
//! about the file. A folder, message or attachment that cannot be opened at
//! all prints an `Error: <Debug>` line of its own, is counted, and the walk
//! continues. The last line is always `Errors: <n>` and the exit status is
//! non-zero if n > 0.
//!
//! What upstream cannot expose, and how it shows here:
//!
//! - Every attachment prints its attachment-table row first (`Row:`), then
//!   the properties read from its own property context. An embedded message
//!   comes back as `Rc<dyn Message>`, which cannot be handed to
//!   `UnicodeAttachment::read` (that needs the concrete type and the message's
//!   crate-private sub-node map), so an embedded message's own attachments
//!   show the `Row:` line only and are not recursed into.
//! - At upstream revision cfb721da, `PropertyType::try_from(u16)` has no arm
//!   for `0x000D` (`PtypObject`) although the enum declares it, and the BTH
//!   leaf walk stops silently at the first undecodable record. Every
//!   embedded-message attachment carries `PidTagAttachDataObject` (0x3701) as
//!   `PtypObject`, so upstream truncates that PC before `PidTagAttachMethod`
//!   and refuses it with `AttachmentMethodNotFound`. The embedded-message
//!   recursion below is therefore unreachable at this pin; the `Row:` line
//!   still records method=5 from the attachment table.

use std::{collections::HashSet, env, io, process::ExitCode, rc::Rc};

use outlook_pst::{
    ltp::{
        prop_context::PropertyValue,
        table_context::{TableContext, TableRowData},
    },
    messaging::{
        attachment::{AnsiAttachment, Attachment, AttachmentData, UnicodeAttachment},
        message::{AnsiMessage, Message, UnicodeMessage},
        store::{AnsiStore, EntryId, Store, UnicodeStore},
    },
    ndb::node_id::{NodeId, NID_ROOT_FOLDER},
    AnsiPstFile, UnicodePstFile,
};

// Property ids, from [MS-OXPROPS], named once so the walk reads as prose. The
// class (0x001A), counts and attach method/size go through upstream's own
// accessors (`message_class()`, `attachment_method()`, ...) instead.
const PR_SUBJECT: u16 = 0x0037;
const PR_CLIENT_SUBMIT_TIME: u16 = 0x0039;
const PR_TRANSPORT_MESSAGE_HEADERS: u16 = 0x007D;
const PR_MESSAGE_DELIVERY_TIME: u16 = 0x0E06;
const PR_NORMALIZED_SUBJECT: u16 = 0x0E1D;
const PR_ATTACH_SIZE: u16 = 0x0E20;
const PR_SENDER_NAME: u16 = 0x0C1A;
const PR_RECIPIENT_TYPE: u16 = 0x0C15;
const PR_SENDER_EMAIL_ADDRESS: u16 = 0x0C1F;
const PR_BODY: u16 = 0x1000;
const PR_RTF_COMPRESSED: u16 = 0x1009;
const PR_HTML: u16 = 0x1013;
const PR_DISPLAY_NAME: u16 = 0x3001;
const PR_EMAIL_ADDRESS: u16 = 0x3003;
const PR_ATTACH_DATA_OBJ: u16 = 0x3701;
const PR_ATTACH_FILENAME: u16 = 0x3704;
const PR_ATTACH_METHOD: u16 = 0x3705;
const PR_ATTACH_LONG_FILENAME: u16 = 0x3707;
const PR_ATTACH_MIME_TAG: u16 = 0x370E;
const PR_ATTACH_CONTENT_ID: u16 = 0x3712;
const PR_SMTP_ADDRESS: u16 = 0x39FE;
const PR_SENDER_SMTP_ADDRESS: u16 = 0x5D01;

/// A folder tree deeper than this is refused: a malformed hierarchy table can
/// point back at an ancestor, and a visited set catches the cycle, but a
/// ceiling catches the pathological-but-acyclic case too.
const MAX_FOLDER_DEPTH: usize = 64;

/// The two file flavours differ only in the concrete types that
/// `Store::open_message` hides behind `Rc<dyn Message>`; reading an
/// attachment needs the concrete message type, so the walk is generic over
/// this small trait rather than over `dyn Store`. Mirrors `open_store`.
trait Flavor {
    type Pst;
    type Store: Store;
    type Message: Message + 'static;
    type Attachment: Attachment;

    fn read_store(pst: Self::Pst) -> io::Result<Rc<Self::Store>>;
    fn open_message(store: &Rc<Self::Store>, entry_id: &EntryId) -> io::Result<Rc<Self::Message>>;
    fn open_attachment(message: &Rc<Self::Message>, node: NodeId) -> io::Result<Rc<Self::Attachment>>;
}

struct Unicode;

impl Flavor for Unicode {
    type Pst = UnicodePstFile;
    type Store = UnicodeStore;
    type Message = UnicodeMessage;
    type Attachment = UnicodeAttachment;

    fn read_store(pst: Self::Pst) -> io::Result<Rc<Self::Store>> {
        UnicodeStore::read(Rc::new(pst))
    }

    fn open_message(store: &Rc<Self::Store>, entry_id: &EntryId) -> io::Result<Rc<Self::Message>> {
        UnicodeMessage::read(store.clone(), entry_id, None)
    }

    fn open_attachment(message: &Rc<Self::Message>, node: NodeId) -> io::Result<Rc<Self::Attachment>> {
        UnicodeAttachment::read(message.clone(), node, None)
    }
}

struct Ansi;

impl Flavor for Ansi {
    type Pst = AnsiPstFile;
    type Store = AnsiStore;
    type Message = AnsiMessage;
    type Attachment = AnsiAttachment;

    fn read_store(pst: Self::Pst) -> io::Result<Rc<Self::Store>> {
        AnsiStore::read(Rc::new(pst))
    }

    fn open_message(store: &Rc<Self::Store>, entry_id: &EntryId) -> io::Result<Rc<Self::Message>> {
        AnsiMessage::read(store.clone(), entry_id, None)
    }

    fn open_attachment(message: &Rc<Self::Message>, node: NodeId) -> io::Result<Rc<Self::Attachment>> {
        AnsiAttachment::read(message.clone(), node, None)
    }
}

/// zlib's CRC-32 (reflected, polynomial 0xEDB88320), i.e. Python's
/// `zlib.crc32` — NOT the [MS-PST] CRC that upstream's private `crc` module
/// computes. Chosen so the Python side can verify a body with the stdlib.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// `None`, or the value's `Debug` form exactly as `read_ipm_subtree` prints it.
fn value_debug(value: Option<&PropertyValue>) -> String {
    match value {
        None => "None".to_string(),
        Some(value) => format!("{value:?}"),
    }
}

/// A body-like property as `<len> bytes crc 0x<crc> type=<variant>`: the raw
/// bytes of the stored value (UTF-16LE for `PtypString`), never its content.
fn bytes_debug(value: Option<&PropertyValue>) -> String {
    let (bytes, kind): (Vec<u8>, &str) = match value {
        None => return "None".to_string(),
        Some(PropertyValue::String8(value)) => (value.buffer().to_vec(), "String8"),
        Some(PropertyValue::Unicode(value)) => (
            value.buffer().iter().flat_map(|unit| unit.to_le_bytes()).collect(),
            "Unicode",
        ),
        Some(PropertyValue::Binary(value)) => (value.buffer().to_vec(), "Binary"),
        other => return value_debug(other),
    };
    format!("{} bytes crc 0x{:08X} type={kind}", bytes.len(), crc32(&bytes))
}

/// An integer-valued property as a bare number (`type=1`, `method=5`),
/// falling back to the `Debug` form when it is absent or not an integer.
fn int_debug(value: Option<&PropertyValue>) -> String {
    match value {
        Some(PropertyValue::Integer32(value)) => value.to_string(),
        other => value_debug(other),
    }
}

fn result_debug<T: std::fmt::Debug>(result: io::Result<T>) -> String {
    match result {
        Ok(value) => format!("{value:?}"),
        Err(err) => format!("Error: {err:?}"),
    }
}

struct Dumper<F: Flavor> {
    store: Rc<F::Store>,
    visited: HashSet<u32>,
    errors: usize,
}

impl<F: Flavor> Dumper<F> {
    fn error(&mut self, indent: usize, err: &dyn std::fmt::Debug) {
        println!("{:indent$}Error: {err:?}", "", indent = indent);
        self.errors += 1;
    }

    /// Read one cell of a table row by property id. `None` when the table has
    /// no such column or the row has no value there; an unreadable cell is an
    /// error on this item.
    fn cell(&mut self, indent: usize, table: &dyn TableContext, row: &TableRowData, prop_id: u16) -> Option<PropertyValue> {
        let context = table.context();
        let index = context.columns().iter().position(|col| col.prop_id() == prop_id)?;
        let columns = match row.columns(context) {
            Ok(columns) => columns,
            Err(err) => {
                self.error(indent, &err);
                return None;
            }
        };
        let value = columns.into_iter().nth(index)??;
        match table.read_column(&value, context.columns()[index].prop_type()) {
            Ok(value) => Some(value),
            Err(err) => {
                self.error(indent, &err);
                None
            }
        }
    }

    fn dump_folder(&mut self, node: NodeId, depth: usize) {
        println!("Folder: {node:?}");
        if depth > MAX_FOLDER_DEPTH {
            self.error(2, &format!("folder depth exceeds {MAX_FOLDER_DEPTH}"));
            return;
        }
        if !self.visited.insert(u32::from(node)) {
            self.error(2, &"folder already visited (cycle in the hierarchy)");
            return;
        }

        let folder = match self
            .store
            .properties()
            .make_entry_id(node)
            .and_then(|entry_id| self.store.open_folder(&entry_id))
        {
            Ok(folder) => folder,
            Err(err) => {
                self.error(2, &err);
                return;
            }
        };

        let properties = folder.properties();
        println!("  Name: {}", result_debug(properties.display_name()));
        println!("  Content Count: {}", result_debug(properties.content_count()));
        println!("  Unread Count: {}", result_debug(properties.unread_count()));
        println!("  Has Sub Folders: {}", result_debug(properties.has_sub_folders()));

        match folder.associated_table() {
            None => println!("  Associated Table: None"),
            Some(table) => println!("  Associated Count: {}", table.rows_matrix().count()),
        }

        match folder.contents_table() {
            None => println!("  Contents Table: None"),
            Some(table) => {
                let nodes: Vec<NodeId> = table
                    .rows_matrix()
                    .map(|row| NodeId::from(u32::from(row.id())))
                    .collect();
                for node in nodes {
                    self.dump_message(node, 2);
                }
            }
        }

        let children: Vec<NodeId> = match folder.hierarchy_table() {
            None => {
                println!("  Hierarchy Table: None");
                Vec::new()
            }
            Some(table) => table
                .rows_matrix()
                .map(|row| NodeId::from(u32::from(row.id())))
                .collect(),
        };
        drop(folder);
        for child in children {
            self.dump_folder(child, depth + 1);
        }
    }

    /// A top-level message: opened through the concrete type so its
    /// attachments can be opened too.
    fn dump_message(&mut self, node: NodeId, indent: usize) {
        println!("{:indent$}Message: {node:?}", "", indent = indent);
        let message = match self
            .store
            .properties()
            .make_entry_id(node)
            .and_then(|entry_id| F::open_message(&self.store, &entry_id))
        {
            Ok(message) => message,
            Err(err) => {
                self.error(indent + 2, &err);
                return;
            }
        };
        self.dump_message_properties(message.as_ref(), indent);
        self.dump_recipients(message.as_ref(), indent);
        self.dump_attachments(message.as_ref(), Some(&message), indent);
    }

    fn dump_message_properties(&mut self, message: &dyn Message, indent: usize) {
        let props = message.properties();
        let p = |label: &str, text: String| println!("{:indent$}{label}: {text}", "", indent = indent + 2);
        p("Class", result_debug(props.message_class()));
        p("Subject", value_debug(props.get(PR_SUBJECT)));
        p("Normalized Subject", value_debug(props.get(PR_NORMALIZED_SUBJECT)));
        p("Sender Name", value_debug(props.get(PR_SENDER_NAME)));
        p("Sender Email", value_debug(props.get(PR_SENDER_EMAIL_ADDRESS)));
        p("Sender SMTP", value_debug(props.get(PR_SENDER_SMTP_ADDRESS)));
        p("Delivery Time", value_debug(props.get(PR_MESSAGE_DELIVERY_TIME)));
        p("Client Submit Time", value_debug(props.get(PR_CLIENT_SUBMIT_TIME)));
        p("Body Text", bytes_debug(props.get(PR_BODY)));
        p("Body HTML", bytes_debug(props.get(PR_HTML)));
        p("Body RTF", bytes_debug(props.get(PR_RTF_COMPRESSED)));
        p("Transport Headers", bytes_debug(props.get(PR_TRANSPORT_MESSAGE_HEADERS)));
    }

    fn dump_recipients(&mut self, message: &dyn Message, indent: usize) {
        let Some(table) = message.recipient_table() else {
            println!("{:indent$}Recipients: None", "", indent = indent + 2);
            return;
        };
        let table = table.clone();
        println!("{:indent$}Recipients: {}", "", table.rows_matrix().count(), indent = indent + 2);
        let rows: Vec<&TableRowData> = table.rows_matrix().collect();
        for row in rows {
            let kind = int_debug(self.cell(indent + 4, table.as_ref(), row, PR_RECIPIENT_TYPE).as_ref());
            let name = value_debug(self.cell(indent + 4, table.as_ref(), row, PR_DISPLAY_NAME).as_ref());
            let email = value_debug(self.cell(indent + 4, table.as_ref(), row, PR_EMAIL_ADDRESS).as_ref());
            let smtp = value_debug(self.cell(indent + 4, table.as_ref(), row, PR_SMTP_ADDRESS).as_ref());
            println!(
                "{:indent$}Recipient: type={kind} name={name} email={email} smtp={smtp}",
                "",
                indent = indent + 4
            );
        }
    }

    /// The attachment table's rows, then each attachment's own property
    /// context when `opener` is a concrete message. An embedded message is
    /// `Rc<dyn Message>` and has no opener: its attachments show the row only.
    fn dump_attachments(&mut self, message: &dyn Message, opener: Option<&Rc<F::Message>>, indent: usize) {
        let Some(table) = message.attachment_table() else {
            println!("{:indent$}Attachments: None", "", indent = indent + 2);
            return;
        };
        let table = table.clone();
        let rows: Vec<&TableRowData> = table.rows_matrix().collect();
        println!("{:indent$}Attachments: {}", "", rows.len(), indent = indent + 2);
        for row in rows {
            let node = NodeId::from(u32::from(row.id()));
            println!("{:indent$}Attachment: {node:?}", "", indent = indent + 4);
            let method = int_debug(self.cell(indent + 6, table.as_ref(), row, PR_ATTACH_METHOD).as_ref());
            let filename = value_debug(self.cell(indent + 6, table.as_ref(), row, PR_ATTACH_FILENAME).as_ref());
            let size = int_debug(self.cell(indent + 6, table.as_ref(), row, PR_ATTACH_SIZE).as_ref());
            println!("{:indent$}Row: method={method} filename={filename} size={size}", "", indent = indent + 6);

            let Some(opener) = opener else {
                println!(
                    "{:indent$}Properties: not opened (embedded message is Rc<dyn Message>)",
                    "",
                    indent = indent + 6
                );
                continue;
            };
            let attachment = match F::open_attachment(opener, node) {
                Ok(attachment) => attachment,
                Err(err) => {
                    self.error(indent + 6, &err);
                    continue;
                }
            };
            let props = attachment.properties();
            let p = |label: &str, text: String| println!("{:indent$}{label}: {text}", "", indent = indent + 6);
            p("Method", result_debug(props.attachment_method()));
            p("Filename", value_debug(props.get(PR_ATTACH_FILENAME)));
            p("Long Filename", value_debug(props.get(PR_ATTACH_LONG_FILENAME)));
            p("Mime Tag", value_debug(props.get(PR_ATTACH_MIME_TAG)));
            p("Content Id", value_debug(props.get(PR_ATTACH_CONTENT_ID)));
            p("Size", result_debug(props.attachment_size()));
            p(
                "Data",
                match attachment.data() {
                    None => "None".to_string(),
                    Some(AttachmentData::Binary(value)) => {
                        format!("{} bytes crc 0x{:08X}", value.buffer().len(), crc32(value.buffer()))
                    }
                    Some(AttachmentData::Message(_)) => "Message".to_string(),
                },
            );
            if let Some(AttachmentData::Message(embedded)) = attachment.data() {
                // The embedded message's node is the PidTagAttachDataObject's.
                let node = match props.get(PR_ATTACH_DATA_OBJ) {
                    Some(PropertyValue::Object(object)) => format!("{:?}", object.node()),
                    other => value_debug(other),
                };
                println!("{:indent$}Message: {node}", "", indent = indent + 6);
                self.dump_message_properties(embedded.as_ref(), indent + 6);
                self.dump_recipients(embedded.as_ref(), indent + 6);
                self.dump_attachments(embedded.as_ref(), None, indent + 6);
            }
        }
    }
}

fn run<F: Flavor>(pst: F::Pst) -> usize {
    let store = match F::read_store(pst) {
        Ok(store) => store,
        Err(err) => {
            println!("Error: {err:?}");
            return 1;
        }
    };
    let mut dumper = Dumper::<F> {
        store,
        visited: HashSet::new(),
        errors: 0,
    };
    dumper.dump_folder(NID_ROOT_FOLDER, 0);
    dumper.errors
}

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: dump_messages <pst>");
        return ExitCode::from(2);
    };

    // The same order as upstream's `open_store`: Unicode first, then ANSI, and
    // the ANSI open's error is the one reported when neither succeeds.
    let errors = match UnicodePstFile::open(&path) {
        Ok(pst) => run::<Unicode>(pst),
        Err(_) => match AnsiPstFile::open(&path) {
            Ok(pst) => run::<Ansi>(pst),
            Err(err) => {
                println!("Error: {err:?}");
                1
            }
        },
    };

    println!("Errors: {errors}");
    if errors == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
