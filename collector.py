import asyncio
import sys

async def read_process_output(cmd, process_line):

	proc = await asyncio.create_subprocess_exec(
		*cmd,
		stdout=asyncio.subprocess.PIPE,
		stderr=asyncio.subprocess.PIPE
	)

	async for raw_line in proc.stdout:
		line = raw_line.decode('utf-8').strip()
		process_line(line)

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

	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)
	try:
		loop.run_until_complete(main())
	except KeyboardInterrupt:
		for task in asyncio.all_tasks(loop):
			task.cancel()
		loop.run_until_complete(asyncio.sleep(0))  # allow cancellation to propagate
		print("Collector stopped by user")
	finally:
		loop.close()
		sys.exit(0)
