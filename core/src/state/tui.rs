//! Groups definitions of the debug text interface
#![cfg(feature = "debug-tui")]

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use futures::executor::block_on;
use itertools::Itertools;
use std::{
    cell::RefCell,
    thread::JoinHandle,
    time::{SystemTime, UNIX_EPOCH},
};
use std::{io::Stdout, thread::Builder as ThreadBuilder, time::Duration};
use tracing::log::{self, LevelFilter};
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem, Row, Table, Tabs},
    Frame, Terminal,
};
use tui_logger::{
    init_logger, TuiLoggerLevelOutput, TuiLoggerSmartWidget, TuiLoggerWidget,
    TuiWidgetEvent as LoggerEvent, TuiWidgetState as SmartLoggerState,
};

use std::io;

use crate::config::RelayerConfig;

use super::RelayerState;

/// A convenience string for ENABLED
const STR_ENABLED: &str = "ENABLED";
/// A convenience string for DISABLED
const STR_DISABLED: &str = "DISABLED";
/// The rate at which to refresh the TUI
const TUI_REFRESH_RATE_MS: u64 = 250; // 3 seconds

// Text style constants
lazy_static! {
    /// Plain green text
    static ref GREEN_TEXT: Style = Style::default().fg(Color::Green);
    /// Plain yellow text
    static ref YELLOW_TEXT: Style = Style::default().fg(Color::Yellow);
    /// Plain blue text
    static ref BLUE_TEXT: Style = Style::default().fg(Color::Blue);
    /// The style of section titles
    static ref TITLE_STYLE: Style = Style::default().fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    /// The style of table headers
    static ref TABLE_HEADER_STYLE: Style = Style::default().fg(Color::Green);
    /// The style of table rows
    static ref TABLE_ROW_STYLE: Style = Style::default().fg(Color::Yellow);
    /// The style of a highlighted element
    static ref HIGHLIGHT_STYLE: Style = Style::default()
        .fg(Color::White)
        .bg(Color::Black)
        .add_modifier(Modifier::BOLD);
}

/// The text user interface app, prints the state at regular intervals
pub struct StateTuiApp {
    /// The selected TUI tab
    selected_tab: AppTab,
    /// The widget state for the smart logger
    smart_logger_state: SmartLoggerState,
    /// A copy of the config passed to the relayer
    config: RelayerConfig,
    /// A copy of the global state to read from
    global_state: RelayerState,
    /// A terminal implementation for creating the TUI
    terminal: RefCell<Terminal<CrosstermBackend<Stdout>>>,
}

/// Defines the tabs available to the app
#[derive(Copy, Clone, Debug)]
pub enum AppTab {
    /// The main tab, all high level relayer information is available
    Main = 0,
    /// The logs tab gives a full screen log view
    Logs,
}

impl AppTab {
    /// Get the list of tab names
    pub fn tab_names() -> Vec<String> {
        vec!["Main", "Logs"]
            .iter()
            .map(|str| str.to_string())
            .collect_vec()
    }
}

impl ToString for AppTab {
    fn to_string(&self) -> String {
        Self::tab_names()[*self as usize].to_owned()
    }
}

impl StateTuiApp {
    /// Create a new instance of the state app
    pub fn new(config: RelayerConfig, global_state: RelayerState) -> Self {
        // Setup the terminal
        enable_raw_mode().unwrap();
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen).unwrap();

        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).unwrap();

        // Setup logging widget
        init_logger(LevelFilter::Info).unwrap();
        Self {
            selected_tab: AppTab::Main,
            smart_logger_state: SmartLoggerState::new(),
            config,
            global_state,
            terminal: RefCell::new(terminal),
        }
    }

    // ------------------
    // | Execution Loop |
    // ------------------

    /// Consume the state TUI in a thread and run an execution loop
    pub fn run(self) -> JoinHandle<()> {
        ThreadBuilder::new()
            .name("state-tui-execution-loop".to_string())
            .spawn(|| self.execution_loop())
            .unwrap()
    }

    /// An implementation of the execution loop
    fn execution_loop(mut self) {
        let timeout = Duration::from_millis(TUI_REFRESH_RATE_MS);
        loop {
            // Borrow the terminal explicitly so that the closure may use self
            let mut term = self.terminal.borrow_mut();
            term.draw(|frame| self.ui(frame)).unwrap();

            // Stop the TUI when 'q' is pressed
            if crossterm::event::poll(timeout).unwrap() {
                if let Event::Key(key) = event::read().unwrap() {
                    log::info!("got here");
                    match key.code {
                        KeyCode::Char('q') => break,
                        // TODO: Switch tab
                        KeyCode::Tab => {
                            self.selected_tab = match self.selected_tab {
                                AppTab::Main => AppTab::Logs,
                                AppTab::Logs => AppTab::Main,
                            }
                        }
                        // Dispatch the state transition to the smart logger if
                        // the logs tab is selected
                        _ => {
                            if let AppTab::Logs = self.selected_tab {
                                let state = &mut self.smart_logger_state;
                                match key.code {
                                    KeyCode::Esc => state.transition(&LoggerEvent::EscapeKey),
                                    // Vim style scrolling
                                    KeyCode::Char('j') => {
                                        state.transition(&LoggerEvent::NextPageKey)
                                    }
                                    KeyCode::Char('k') => {
                                        state.transition(&LoggerEvent::PrevPageKey)
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }

        // Restore the terminal state
        disable_raw_mode().unwrap();
        execute!(
            self.terminal.borrow_mut().backend_mut(),
            LeaveAlternateScreen,
        )
        .unwrap();
        self.terminal.borrow_mut().show_cursor().unwrap();
    }

    // -------------------------
    // | Rendering and Widgets |
    // -------------------------

    /// Build the UI on a frame render tick
    fn ui<B: Backend>(&self, frame: &mut Frame<B>) {
        // Dispatch based on the selected tab
        match self.selected_tab {
            AppTab::Main => self.main_tab(frame),
            AppTab::Logs => self.logs_tab(frame),
        }
    }

    /// Render the main tab
    fn main_tab<B: Backend>(&self, frame: &mut Frame<B>) {
        // Chunk into four vertical rows
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![
                Constraint::Percentage(5),
                Constraint::Percentage(25),
                Constraint::Percentage(30),
                Constraint::Percentage(40),
            ])
            .split(frame.size());

        // Split out the chunks
        let tab_select = chunks[0];
        let top_row = chunks[1];
        let middle_row = chunks[2];
        let bottom_row = chunks[3];

        // -------------------
        // | Tab Select Pane |
        // -------------------
        let tab_pane = self.create_tab_selection();
        frame.render_widget(tab_pane, tab_select);

        // -----------------
        // | Top Row Panes |
        // -----------------
        // Split the top row into two panes horizontally
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(top_row);
        let top_left = chunks[0];
        let top_right = chunks[1];

        // Build a metadata section
        let metadata_pane = self.create_metadata_pane();
        frame.render_widget(metadata_pane, top_left);

        // Build a cluster metadata section
        let cluster_metadata_pane = self.create_cluster_metadata_pane();
        frame.render_widget(cluster_metadata_pane, top_right);

        // --------------------
        // | Middle Row Panes |
        // --------------------

        // Split the middle row into two panes
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(middle_row);
        let mid_left = chunks[0];
        let mid_right = chunks[1];

        // Build a peer index pane
        let peer_index_pane = self.create_peer_index_pane();
        frame.render_widget(peer_index_pane, mid_left);

        // Build an orderbook pane
        let order_book_pane = self.create_order_book_pane();
        frame.render_widget(order_book_pane, mid_right);

        // -------------------
        // | Bottom Row Pane |
        // -------------------

        // Build a logs section
        let log_widget = Self::create_log_widget();
        frame.render_widget(log_widget, bottom_row);
    }

    /// Render the logs tab, a full screen view of the relayer logs
    fn logs_tab<B: Backend>(&self, frame: &mut Frame<B>) {
        // Chunk into two vertical rows, one for tab select, one for logs
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![Constraint::Percentage(5), Constraint::Percentage(95)])
            .split(frame.size());

        // Split out the chunks
        let tab_select_pane = chunks[0];
        let logs_pane = chunks[1];

        let tab_select = self.create_tab_selection();
        let log_widget = self.create_smart_log_widget();

        // Render into the chunks
        frame.render_widget(tab_select, tab_select_pane);
        frame.render_widget(log_widget, logs_pane);
    }

    /// Create a new, default block with the given title
    fn create_block_with_title(title: &str) -> Block {
        let styled_title = Span::styled(title, *TITLE_STYLE);
        Block::default()
            .title(styled_title)
            .borders(Borders::all())
            .border_style(Style::default().add_modifier(Modifier::BOLD))
            .style(Style::default().fg(Color::LightYellow))
            .title_alignment(Alignment::Center)
    }

    /// Create a tab selection pane
    fn create_tab_selection(&self) -> Tabs {
        let tab_names = AppTab::tab_names()
            .into_iter()
            .map(Spans::from)
            .collect_vec();

        Tabs::new(tab_names)
            .block(Self::create_block_with_title("Tabs"))
            .select(self.selected_tab as usize)
            .highlight_style(*HIGHLIGHT_STYLE)
            .divider("|")
    }

    /// Create a metadata pane
    fn create_metadata_pane(&self) -> List {
        // Fetch the relevant state
        let peer_id = self.global_state.local_peer_id();
        let cluster_id = self.global_state.local_cluster_id.clone();
        let local_addr = block_on(async {
            self.global_state
                .read_peer_index()
                .await
                .get_peer_info(&peer_id)
                .await
                .unwrap_or_default()
                .get_addr()
        });
        let full_addr = format!("{local_addr}/p2p/{peer_id}");
        let api_server_enabled = if self.config.disable_api_server {
            STR_DISABLED
        } else {
            STR_ENABLED
        };
        let price_reporter_enabled = if self.config.disable_price_reporter {
            STR_DISABLED
        } else {
            STR_ENABLED
        };
        let chain_events_enabled = if self.config.starknet_jsonrpc_node.is_some() {
            STR_ENABLED
        } else {
            STR_DISABLED
        };

        // Style and collect into a list
        let line1 = Spans::from(vec![
            Span::styled("Listening on: ", *GREEN_TEXT),
            Span::styled(full_addr, *YELLOW_TEXT),
        ]);
        let line2 = Spans::from(vec![
            Span::styled("Peer ID: ", *GREEN_TEXT),
            Span::styled(peer_id.to_string(), *YELLOW_TEXT),
        ]);
        let line3 = Spans::from(vec![
            Span::styled("Cluster ID: ", *GREEN_TEXT),
            Span::styled(cluster_id.to_string(), *YELLOW_TEXT),
        ]);
        let line4 = Spans::from(vec![
            Span::styled("P2P Port: ", *GREEN_TEXT),
            Span::styled(self.config.p2p_port.to_string(), *YELLOW_TEXT),
        ]);
        let line5 = Spans::from(vec![
            Span::styled("HTTP Port: ", *GREEN_TEXT),
            Span::styled(self.config.http_port.to_string(), *YELLOW_TEXT),
        ]);
        let line6 = Spans::from(vec![
            Span::styled("Websocket Port: ", *GREEN_TEXT),
            Span::styled(self.config.websocket_port.to_string(), *YELLOW_TEXT),
        ]);
        let line7 = Spans::from(vec![
            Span::styled("API Server: ", *GREEN_TEXT),
            Span::styled(api_server_enabled, *YELLOW_TEXT),
        ]);
        let line8 = Spans::from(vec![
            Span::styled("Price reporter: ", *GREEN_TEXT),
            Span::styled(price_reporter_enabled, *YELLOW_TEXT),
        ]);
        let line9 = Spans::from(vec![
            Span::styled("StarkNet Events Listener: ", *GREEN_TEXT),
            Span::styled(chain_events_enabled, *YELLOW_TEXT),
        ]);

        let items = vec![
            ListItem::new(line1),
            ListItem::new(line2),
            ListItem::new(line3),
            ListItem::new(line4),
            ListItem::new(line5),
            ListItem::new(line6),
            ListItem::new(line7),
            ListItem::new(line8),
            ListItem::new(line9),
        ];

        List::new(items).block(Self::create_block_with_title("Local Node Metadata"))
    }

    /// Create a cluster metadata pane    
    fn create_cluster_metadata_pane(&self) -> List {
        // Read the relevant state
        let cluster_id = self.global_state.local_cluster_id.clone();
        let cluster_peers = block_on(async {
            self.global_state
                .read_peer_index()
                .await
                .get_all_cluster_peers(&cluster_id)
                .await
        });

        // Style and collect into a list
        let line1 = Spans::from(vec![
            Span::styled("Cluster ID: ", *GREEN_TEXT),
            Span::styled(cluster_id.to_string(), *YELLOW_TEXT),
        ]);
        let line2 = Span::styled("Cluster Peers:", *GREEN_TEXT);
        let mut items = vec![ListItem::new(line1), ListItem::new(line2)];

        // Add all cluster peers
        for peer in cluster_peers.iter() {
            let line = Span::styled(format!(" - {peer}"), *BLUE_TEXT);
            items.push(ListItem::new(line));
        }

        List::new(items).block(Self::create_block_with_title("Cluster Metadata"))
    }

    /// Create a peer index pane    
    fn create_peer_index_pane(&self) -> Table {
        // Read the necessary state
        let local_peer_id = self.global_state.local_peer_id();
        let peer_info = block_on(async {
            self.global_state
                .read_peer_index()
                .await
                .get_info_map()
                .await
        });

        // Sort the keys so that the table does not re-arrange every frame
        let mut sorted_keys = peer_info.keys().cloned().collect_vec();
        sorted_keys.sort();

        // Collect into a table
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut rows = Vec::new();
        for (peer_id, info) in sorted_keys
            .iter()
            .map(|key| (key, peer_info.get(key).unwrap()))
        {
            let last_heartbeat_elapsed = if peer_id.ne(&local_peer_id) {
                (now - info.get_last_heartbeat()) * 1000
            } else {
                0
            };

            let row = Row::new(vec![
                peer_id.to_string(),
                format!("{last_heartbeat_elapsed} ms"),
            ])
            .style(*TABLE_ROW_STYLE);
            rows.push(row);
        }

        Table::new(rows)
            .header(
                Row::new(vec!["Peer", "Last Heartbeat"])
                    .style(*TABLE_HEADER_STYLE)
                    .bottom_margin(1),
            )
            .block(Self::create_block_with_title("Peer Index"))
            .widths(&[Constraint::Percentage(50), Constraint::Percentage(50)])
            .column_spacing(5)
    }

    /// Create an order book pane
    fn create_order_book_pane(&self) -> Table {
        // Read the necessary state
        let order_book = block_on(async {
            self.global_state
                .read_order_book()
                .await
                .get_order_book_snapshot()
                .await
        });

        let mut sorted_keys = order_book.keys().clone().collect_vec();
        sorted_keys.sort();

        // Style and collect into a table
        let mut rows = Vec::new();
        for (order_id, info) in sorted_keys
            .iter()
            .map(|key| (*key, order_book.get(key).unwrap()))
        {
            let local_nonlocal = if info.local { "local" } else { "nonlocal" }.to_string();
            let row = Row::new(vec![
                order_id.to_string(),
                info.state.to_string(),
                local_nonlocal,
            ])
            .style(*TABLE_ROW_STYLE);

            rows.push(row)
        }

        Table::new(rows)
            .header(
                Row::new(vec!["Order ID", "State", "Management"])
                    .style(*TABLE_HEADER_STYLE)
                    .bottom_margin(1),
            )
            .block(Self::create_block_with_title("Order Book"))
            .widths(&[
                Constraint::Percentage(33),
                Constraint::Percentage(33),
                Constraint::Percentage(33),
            ])
            .column_spacing(5)
    }

    /// Create a log widget that dumps the system logs
    fn create_log_widget<'a>() -> TuiLoggerWidget<'a> {
        TuiLoggerWidget::default()
            .block(Self::create_block_with_title("Logs"))
            .style_info(Style::default().fg(Color::Blue))
            .style_warn(Style::default().fg(Color::Yellow))
            .style_error(Style::default().fg(Color::Red))
            .output_timestamp(Some("%Y-%m-%dT%H:%M:%S".to_string()))
            .output_file(false)
            .output_target(false)
            .output_line(false)
            .output_separator(' ')
    }

    /// Create a smart logger widget that gives more control over the log view
    fn create_smart_log_widget<'a>(&self) -> TuiLoggerSmartWidget<'a> {
        TuiLoggerSmartWidget::default()
            .style_error(Style::default().fg(Color::Red))
            .style_debug(Style::default().fg(Color::Green))
            .style_warn(Style::default().fg(Color::Yellow))
            .style_trace(Style::default().fg(Color::Magenta))
            .style_info(Style::default().fg(Color::Cyan))
            .output_separator(':')
            .output_timestamp(Some("%H:%M:%S".to_string()))
            .output_level(Some(TuiLoggerLevelOutput::Abbreviated))
            .output_target(true)
            .output_line(true)
            .state(&self.smart_logger_state)
    }
}
