<?php

class Session {

	private $table = "sessions";
	private $expire = 60;
	private $internalExpire = 7200;
	private $salt = 'SaltSaltSalt'; // session' key salt
	private $dbs = 0;
	private $sid = "";
	private $_SESS_VARS = array();
	private $authorized = 0;
	private $user_id = 0;
	private $writes_count = 0;
	private $client_id = '';

	/**
	 * Class constructor
	 *
	 * @param string $sid User' session key
	 * @param string $client_id The name of storage scope
	 * @param bool $bRenewSession Need to prolong the session
	 * @return Session
	 */
	function __construct($sid, $client_id = 'default', $bRenewSession = true, $bIsAdminSession = false) {
		global $config;
		$this->expire = $config['session_time'];
		if ($this->expire == 0)
			$this->expire = $this->internalExpire;

		$this->table = $config['mysql_session_table'];

		$this->kill_expired($bIsAdminSession);
		$this->client_id = $client_id;

		if (!strlen($this->client_id)) {
			Log::error("Bad client ID in class Sessions.");
		} elseif (preg_match("/^[a-z0-9]+$/i", $sid) && (strlen($sid) == 32)) { // Check string format
			$sid_q = Mysql::real_escape_string($sid);

			Mysql::query("SELECT * FROM {$this->table} WHERE session_id = '$sid_q' LIMIT 1;");

			if ( $DBData = Mysql::fetch_object() ) {

				if ($DBData->fingerprint == $this->gen_fingerprint($sid)) {
					$this->user_id = (int) $DBData->user_id;
					$this->authorized = 1;

					// -------------------

					$tmp_var = unserialize($DBData->data);
					if (!isset($tmp_var[$this->client_id])) {
						$tmp_var[$this->client_id] = array();
					}

					$this->_SESS_VARS = $tmp_var[$this->client_id];
					unset($tmp_var);

					// -------------------
					$this->sid = strtolower($DBData->session_id);
					if ($bRenewSession) {
						Mysql::query("UPDATE {$this->table} SET expire=(UNIX_TIMESTAMP() + {$this->expire}) WHERE session_id='$sid_q';");
					}
				}
			}
		} elseif (strlen($sid) <> 32) {
		//	Log::debug("sid error sid len: ".strlen($sid)."; request_url: ".$_SERVER["REQUEST_URI"]);
		} elseif(!preg_match("/^[a-z0-9]+$/i", $sid)) {
			Log::debug("sid error preg_match error: ".preg_match("/^[a-z0-9]+$/i", $sid)."; request_url: ".$_SERVER["REQUEST_URI"]);
		}
	}

	public function create($user_id) {

		$user_id = (int) $user_id;
		if (!$this->authorized && $user_id) {

			$this->sid = $this->gen_sid();
			$fingerprint = Mysql::real_escape_string($this->gen_fingerprint($this->sid));

			$sid_q = Mysql::real_escape_string($this->sid); // $db->real_escape_string();

			$remote_addr = Mysql::real_escape_string($_SERVER['REMOTE_ADDR']);
			$user_agent = Mysql::real_escape_string($_SERVER['HTTP_USER_AGENT']);

			$tmp_var = array($this->client_id => array());
			$data_q = Mysql::real_escape_string(serialize($tmp_var));

			Mysql::query("INSERT INTO $this->table
					SET
						session_id = '$sid_q',
						user_id = $user_id,
						data = '$data_q',
						expire=(UNIX_TIMESTAMP() + {$this->expire}),
						ip = '$remote_addr',
						user_agent = '$user_agent',
						fingerprint = '$fingerprint';
			");

			$this->authorized = 1;
		}
	}

	public function get_authorized() {
		return $this->authorized;
	}

	public function get_user_id() {
		return $this->user_id;
	}

	private function gen_sid() {
		global $_SERVER, $iDBTime;
		return md5(rand(1, 99999999) . $this->secret . $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'] . $iDBTime);
	}

	private function gen_fingerprint($sid) {
		global $_SERVER;
		return md5($this->secret . $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'] . $sid);
	}

	public function get_sid() {
		return $this->sid;
	}

	public function set_var($var_name, $var_value) {
		if ($this->authorized && strlen($var_name)) {
			$this->_SESS_VARS[$var_name] = $var_value;
			$this->writes_count++;

			//print_r($this->_SESS_VARS);
			return true;
		}

		return false;
	}

	public function get_var($var_name) {
		if ($this->authorized && strlen($var_name) && isset($this->_SESS_VARS[$var_name]))
			return $this->_SESS_VARS[$var_name];
		return false;
	}

	public function unset_var($var_name) {
		if ($this->authorized && strlen($var_name) && isset($this->_SESS_VARS[$var_name])) {
			$this->writes_count++;
			unset($this->_SESS_VARS[$var_name]);
			return true;
		}
		return false;
	}

	public function clear_vars() {
		if ($this->authorized && is_array($this->_SESS_VARS)) {
			$this->writes_count++;
			$this->_SESS_VARS = array();
			return true;
		}
		return false;
	}

	public function write() {
		if ($this->authorized && $this->writes_count) {
			$sid_q = Mysql::real_escape_string($this->sid);


			$this->writes_count = 0;

			//Mysql::query("LOCK TABLES {$this->table} READ, {$this->table} WRITE;");

			Mysql::query("SELECT data FROM {$this->table} WHERE session_id = '$sid_q' LIMIT 1;");

			$DBData = Mysql::fetch_object();

			$tmp_var = unserialize($DBData->data);

			if (is_array($tmp_var)) {
				$tmp_var[$this->client_id] = $this->_SESS_VARS;
			} else {
				$tmp_var = array();
				$tmp_var[$this->client_id] = $this->_SESS_VARS;
			}
			//print_r($tmp_var);

			$sess_data_q = Mysql::real_escape_string(serialize($tmp_var));
			Mysql::query("UPDATE {$this->table} SET data='$sess_data_q' WHERE session_id='$sid_q';");

			//Mysql::query("UNLOCK TABLES;");
		}

		return false;
	}

	private function kill_expired() {
		Mysql::query("DELETE FROM {$this->table} WHERE expire < UNIX_TIMESTAMP();");
	}

	public function destroy() {
		if ($this->authorized) {
			$this->authorized = 0;
			$this->user_id = 0;

			$sid_q = Mysql::real_escape_string($this->sid);
			$this->sid = '';

			return Mysql::query("DELETE FROM {$this->table} WHERE session_id='$sid_q';");
		}

		return false;
	}

	public function __destruct() {
		//if ( $this->dbs ) {
		$this->write();
		//Mysql::disconnect(); //  @mysql_close($this->dbs);
		//}
	}

}

?>