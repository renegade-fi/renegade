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
    style::{Color, Style},
    widgets::{Block, Borders},
    Frame, Terminal,
};
use tui_logger::{init_logger, TuiLoggerWidget};

use std::io;

use super::RelayerState;

/// The rate at which to refresh the TUI
const TUI_REFRESH_RATE_MS: u64 = 250; // 3 seconds

/// The text user interface app, prints the state at regular intervals
pub struct StateTuiApp {
    /// A copy of the global state to read from
    global_state: RelayerState,
    /// A terminal implementation for creating the TUI
    terminal: RefCell<Terminal<CrosstermBackend<Stdout>>>,
}

impl StateTuiApp {
    /// Create a new instance of the state app
    pub fn new(global_state: RelayerState) -> Self {
        // Setup the terminal
        enable_raw_mode().unwrap();
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen).unwrap();

        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).unwrap();

        // Setup logging widget
        init_logger(LevelFilter::Info).unwrap();
        Self {
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
        // Chunk into two sections, one for logs
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(2)
            .constraints(vec![Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(frame.size());

        let main_chunk = chunks[0];
        let log_chunk = chunks[1];

        // Build a logs section
        // let log_paragraph = self.log_capture_section(log_chunk.height as usize);
        let log_widget = TuiLoggerWidget::default()
            .block(Self::create_block_with_title("Logs"))
            .style_info(Style::default().fg(Color::Blue))
            .style_warn(Style::default().fg(Color::Yellow))
            .style_error(Style::default().fg(Color::Red))
            .output_timestamp(Some("%Y-%m-%dT%H:%M:%S".to_string()))
            .output_file(false)
            .output_target(false)
            .output_line(false)
            .output_separator(' ');

        frame.render_widget(log_widget, log_chunk);
    }

    /// Create a new, default block with the given title
    fn create_block_with_title(title: &str) -> Block {
        Block::default()
            .title(title)
            .borders(Borders::all())
            .title_alignment(Alignment::Center)
    }
}
