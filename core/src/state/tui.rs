//! Groups definitions of the debug text interface
#![cfg(feature = "debug-tui")]

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::cell::RefCell;
use std::{io::Stdout, thread::Builder as ThreadBuilder, time::Duration};
use tracing::log::LevelFilter;
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem},
    Frame, Terminal,
};
use tui_logger::{init_logger, TuiLoggerWidget};

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
}

// -----------------
// | Color Aliases |
// -----------------

/// The text user interface app, prints the state at regular intervals
pub struct StateTuiApp {
    /// A copy of the config passed to the relayer
    config: RelayerConfig,
    /// A copy of the global state to read from
    global_state: RelayerState,
    /// A terminal implementation for creating the TUI
    terminal: RefCell<Terminal<CrosstermBackend<Stdout>>>,
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
            config,
            global_state,
            terminal: RefCell::new(terminal),
        }
    }

    // ------------------
    // | Execution Loop |
    // ------------------

    /// Consume the state TUI in a thread and run an execution loop
    pub fn run(self) {
        ThreadBuilder::new()
            .name("state-tui-execution-loop".to_string())
            .spawn(|| self.execution_loop())
            .unwrap();
    }

    /// An implementation of the execution loop
    fn execution_loop(self) {
        let timeout = Duration::from_millis(TUI_REFRESH_RATE_MS);
        loop {
            // Borrow the terminal explicitly so that the closure may use self
            let mut term = self.terminal.borrow_mut();
            term.draw(|frame| self.ui(frame)).unwrap();

            // Stop the TUI when 'q' is pressed
            if crossterm::event::poll(timeout).unwrap() {
                if let Event::Key(key) = event::read().unwrap() {
                    if let KeyCode::Char('q') = key.code {
                        println!("Quitting");
                        break;
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
        // Chunk into three vertical rows
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![
                Constraint::Percentage(25),
                Constraint::Percentage(35),
                Constraint::Percentage(40),
            ])
            .split(frame.size());

        // Split out the chunks
        let top_row = chunks[0];
        let middle_row = chunks[1];
        let bottom_row = chunks[2];

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

        // -------------------
        // | Bottom Row Pane |
        // -------------------

        // Build a logs section
        let log_widget = Self::create_log_widget();
        frame.render_widget(log_widget, bottom_row);
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

    /// Create a metadata pane
    fn create_metadata_pane(&self) -> List {
        // Fetch the relevant state
        let peer_id = self.global_state.local_peer_id();
        let cluster_id = self.global_state.local_cluster_id.clone();
        let local_addr = {
            self.global_state
                .read_peer_index()
                .get_peer_info(&peer_id)
                .unwrap_or_default()
                .get_addr()
        };
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
        let chain_events_enabled = if self.config.starknet_gateway.is_some() {
            STR_ENABLED
        } else {
            STR_DISABLED
        };

        // Style and collect into a list
        let line1 = Spans::from(vec![
            Span::styled("Listening on: ", *GREEN_TEXT),
            Span::styled(local_addr.to_string(), *YELLOW_TEXT),
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
        let cluster_peers = {
            self.global_state
                .read_peer_index()
                .get_all_cluster_peers(&cluster_id)
        };

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
}
