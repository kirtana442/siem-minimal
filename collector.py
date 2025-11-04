import asyncio

async def read_process_output(cmd, process_line):

	proc = await asyncio.create_subprocess_exec(
		*cmd,
		stdout=asyncio.subprocess.PIPE,
		stderr=asyncio.subprocess.PIPE,
		text=True
	)

	async for line in proc.stdout:
		process_line(line.strip())

	await proc.wait()

def process_line(line):

	print(f"Log: {line}");

async def get_ssh_logs():

	cmd = [ "journalctl", "-u", "ssh.service", "--no-pager", "-f", "--since", "now"]
	await read_process_output(cmd,process_line)

async def get_sudo_logs():

	cmd = [
		"journalctl",
		"-t", "sudo",
		"--no-pager",
		"-f",
		"--since", "now"]
	await read_process_output(cmd,process_line)

async def main():
	await asyncio.gather(
		get_ssh_logs(),
		get_sudo_logs(),)

if __name__ == "__main__":

	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print("Collector stopped by user")
