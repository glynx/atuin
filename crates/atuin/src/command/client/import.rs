use std::borrow::Cow;
use std::env;

use async_trait::async_trait;
use atuin_client::database::Sqlite;
use atuin_client::history::History;
use atuin_client::import::bash::Bash;
use atuin_client::import::fish::Fish;
use atuin_client::import::nu::Nu;
use atuin_client::import::nu_histdb::NuHistDb;
use atuin_client::import::powershell::PowerShell;
use atuin_client::import::replxx::Replxx;
use atuin_client::import::resh::Resh;
use atuin_client::import::xonsh::Xonsh;
use atuin_client::import::xonsh_sqlite::XonshSqlite;
use atuin_client::import::zsh::Zsh;
use atuin_client::import::zsh_histdb::ZshHistDb;
use atuin_client::import::{Importer, Loader};
use atuin_client::settings::Security;
use clap::Parser;
use easy_cast::Conv;
use eyre::Result;
use indicatif::ProgressBar;
use tracing::instrument;

use crate::i18n::fl;

#[derive(Parser, Debug)]
#[command(infer_subcommands = true)]
pub enum Cmd {
    #[command(about = fl!("cmd-import-auto"))]
    Auto,

    #[command(about = fl!("cmd-import-shell", shell = "zsh"))]
    Zsh,
    #[command(about = fl!("cmd-import-zsh-hist-db"))]
    ZshHistDb,
    #[command(about = fl!("cmd-import-shell", shell = "bash"))]
    Bash,
    #[command(about = fl!("cmd-import-shell", shell = "replxx"))]
    Replxx,
    #[command(about = fl!("cmd-import-shell", shell = "resh"))]
    Resh,
    #[command(about = fl!("cmd-import-shell", shell = "fish"))]
    Fish,
    #[command(about = fl!("cmd-import-shell", shell = "nu"))]
    Nu,
    #[command(about = fl!("cmd-import-nu-hist-db"))]
    NuHistDb,
    #[command(about = fl!("cmd-import-xonsh"))]
    Xonsh,
    #[command(about = fl!("cmd-import-xonsh-sqlite"))]
    XonshSqlite,
    #[command(about = fl!("cmd-import-shell", shell = "powershell"))]
    Powershell,
}

const BATCH_SIZE: usize = 100;

impl Cmd {
    #[allow(clippy::cognitive_complexity)]
    #[instrument(level = "trace", skip_all, err)]
    pub async fn run(&self, db: &Sqlite, security: &Security) -> Result<()> {
        println!("        Atuin         ");
        println!("======================");
        println!("          \u{1f30d}          ");
        println!("       \u{1f418}\u{1f418}\u{1f418}\u{1f418}       ");
        println!("          \u{1f422}          ");
        println!("======================");
        println!("Importing history...");

        match self {
            Self::Auto => {
                if cfg!(windows) {
                    return if env::var("PSModulePath").is_ok() {
                        println!("Detected PowerShell");
                        import::<PowerShell>(db, security).await
                    } else {
                        println!("Could not detect the current shell.");
                        println!("Please run atuin import <SHELL>.");
                        println!("To view a list of shells, run atuin import.");
                        Ok(())
                    };
                }

                // $XONSH_HISTORY_BACKEND isn't always set, but $XONSH_HISTORY_FILE is
                let xonsh_histfile =
                    env::var("XONSH_HISTORY_FILE").unwrap_or_else(|_| String::new());
                let shell = env::var("SHELL").unwrap_or_else(|_| String::from("NO_SHELL"));

                if xonsh_histfile.to_lowercase().ends_with(".json") {
                    println!("Detected Xonsh");
                    import::<Xonsh>(db, security).await
                } else if xonsh_histfile.to_lowercase().ends_with(".sqlite") {
                    println!("Detected Xonsh (SQLite backend)");
                    import::<XonshSqlite>(db, security).await
                } else if shell.ends_with("/zsh") {
                    if let Ok(path) = ZshHistDb::histpath() {
                        println!("Detected Zsh-HistDb, using :{}", path.to_string_lossy());
                        import::<ZshHistDb>(db, security).await
                    } else {
                        println!("Detected ZSH");
                        import::<Zsh>(db, security).await
                    }
                } else if shell.ends_with("/fish") {
                    println!("Detected Fish");
                    import::<Fish>(db, security).await
                } else if shell.ends_with("/bash") {
                    println!("Detected Bash");
                    import::<Bash>(db, security).await
                } else if shell.ends_with("/nu") {
                    if let Ok(path) = NuHistDb::histpath() {
                        println!("Detected Nu-HistDb, using :{}", path.to_string_lossy());
                        import::<NuHistDb>(db, security).await
                    } else {
                        println!("Detected Nushell");
                        import::<Nu>(db, security).await
                    }
                } else if shell.ends_with("/pwsh") {
                    println!("Detected PowerShell");
                    import::<PowerShell>(db, security).await
                } else {
                    println!("cannot import {shell} history");
                    Ok(())
                }
            }

            Self::Zsh => import::<Zsh>(db, security).await,
            Self::ZshHistDb => import::<ZshHistDb>(db, security).await,
            Self::Bash => import::<Bash>(db, security).await,
            Self::Replxx => import::<Replxx>(db, security).await,
            Self::Resh => import::<Resh>(db, security).await,
            Self::Fish => import::<Fish>(db, security).await,
            Self::Nu => import::<Nu>(db, security).await,
            Self::NuHistDb => import::<NuHistDb>(db, security).await,
            Self::Xonsh => import::<Xonsh>(db, security).await,
            Self::XonshSqlite => import::<XonshSqlite>(db, security).await,
            Self::Powershell => import::<PowerShell>(db, security).await,
        }
    }
}

pub struct HistoryImporter<'db> {
    pb: ProgressBar,
    buf: Vec<History>,
    db: &'db Sqlite,
    security: &'db Security,
}

impl<'db> HistoryImporter<'db> {
    fn new(db: &'db Sqlite, security: &'db Security, len: usize) -> Self {
        Self {
            pb: ProgressBar::new(u64::conv(len)),
            buf: Vec::with_capacity(BATCH_SIZE),
            db,
            security,
        }
    }

    async fn flush(self) -> Result<()> {
        self.db.save_bulk(&self.buf).await?;
        self.pb.finish();
        Ok(())
    }
}

#[async_trait]
impl Loader for HistoryImporter<'_> {
    async fn push(&mut self, mut hist: History) -> Result<()> {
        self.pb.inc(1);
        // Imported history is kept as the user's own patterns rewrite it, like the rest.
        let redacted = match self.security.redact_command(&hist.command) {
            Some(Cow::Borrowed(_)) => None,
            Some(Cow::Owned(command)) => Some(command),
            None => return Ok(()),
        };
        if let Some(command) = redacted {
            hist.command = command;
        }
        self.buf.push(hist);
        if self.buf.len() == self.buf.capacity() {
            self.db.save_bulk(&self.buf).await?;
            self.buf.clear();
        }
        Ok(())
    }
}

async fn import<I: Importer + Send>(db: &Sqlite, security: &Security) -> Result<()> {
    println!("Importing history from {}", I::NAME);

    let mut importer = I::new().await?;
    let len = importer.entries().await?;
    let mut loader = HistoryImporter::new(db, security, len);
    importer.load(&mut loader).await?;
    loader.flush().await?;

    println!("Import complete!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use atuin_common::secrets::RedactPattern;
    use rstest::rstest;
    use time::OffsetDateTime;

    use super::*;

    /// Imported history is stored as the user's patterns rewrite it, like captured history.
    #[rstest]
    #[tokio::test]
    async fn imported_commands_are_redacted() {
        let db = Sqlite::in_memory(Duration::from_secs(2)).await.unwrap();
        let security = Security {
            redact_patterns: vec![
                RedactPattern::with_replacement(
                    regex::Regex::new(r"(--password=)\S+").unwrap(),
                    "${1}<PASSWORD>".to_owned(),
                )
                .unwrap(),
            ],
            ..Security::default()
        };
        let mut loader = HistoryImporter::new(&db, &security, 2);
        let now = OffsetDateTime::now_utc();
        for (offset, command) in [(1, "mysql --password=hunter2 db"), (2, "ls -la")] {
            let entry = History::import()
                .timestamp(now - time::Duration::seconds(offset))
                .command(command)
                .build();
            loader.push(entry.into()).await.unwrap();
        }
        loader.flush().await.unwrap();

        let mut stored: Vec<String> = db
            .before(now + time::Duration::SECOND, 10)
            .await
            .unwrap()
            .into_iter()
            .map(|h| h.command)
            .collect();
        stored.sort();
        assert_eq!(stored, ["ls -la", "mysql --password=<PASSWORD> db"]);
    }
}
