use clap::{Parser, Subcommand};
use std::process::Command;

/// Ironpost 빌드 태스크
#[derive(Parser)]
#[command(name = "xtask")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 전체 프로젝트 빌드 (eBPF 제외)
    Build {
        /// 릴리스 모드로 빌드
        #[arg(long)]
        release: bool,

        /// eBPF 커널 프로그램 포함 (Linux 전용)
        #[arg(long)]
        all: bool,
    },

    /// eBPF 커널 프로그램만 빌드 (Linux 전용)
    BuildEbpf {
        /// 릴리스 모드로 빌드
        #[arg(long)]
        release: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Build { release, all } => {
            build_workspace(release);
            if all {
                println!("\nBuilding eBPF kernel program...");
                build_ebpf(release);
            }
        }
        Commands::BuildEbpf { release } => {
            build_ebpf(release);
        }
    }
}

fn build_workspace(release: bool) {
    let mut cmd = Command::new("cargo");

    cmd.args(["build", "--workspace"]);

    if release {
        cmd.arg("--release");
    }

    println!("Building workspace...");
    let status = cmd.status().expect("failed to build workspace");
    if !status.success() {
        eprintln!("Workspace build failed");
        std::process::exit(1);
    }

    println!("Workspace build succeeded");
}

fn build_ebpf(release: bool) {
    let mut cmd = Command::new("cargo");
    cmd.current_dir("crates/ebpf-engine/ebpf");

    cmd.args([
        "+nightly",
        "build",
        "--target=bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().expect("failed to build eBPF program");
    if !status.success() {
        eprintln!("eBPF build failed");
        std::process::exit(1);
    }

    println!("eBPF build succeeded");
}
