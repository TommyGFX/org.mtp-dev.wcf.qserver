<?php
class QServerUtil {
	private $admin;
	
	private $socket, $numeric;

	private static $instance = null;

	public static function getInstance($login = true) {
		if(self::$instance === null) {
			self::$instance = new QServerUtil($login);
		}
		return self::$instance;
	}
	
 	public function __construct($login = true) {
  		$this->admin['user']=QSERVER_USERNAME;
  		$this->admin['pass']=QSERVER_AUTHPASS;
  		$this->admin['spass']=QSERVER_PASS;
  		$this->admin['host']=QSERVER_SERVER;
  		$this->admin['port']=QSERVER_PORT;
  		
  		$this->connect($login);
 	}
 	
 	public function __destruct() {
 		$this->disconnect();
 	}
 	
 	public function disconnect() {
  		fclose($this->socket);
  		$this->socket=false;
 	}
 
 	public function connect($auth = true) {
 		if($this->socket) {
   			$this->disconnect();
  		}
  		$this->socket=@fsockopen($this->admin['host'], $this->admin['port'], $errno, $errstr, 3);
  		if ($this->socket) {
   			stream_set_timeout($this->socket,2);
   			$this->numeric=rand(10,99);
   			fputs($this->socket,$this->numeric." PASS ".$this->admin['spass']."\n");
   			if($auth) $this->command("AuthServ","AUTH ".$this->admin['user']." ".$this->admin['pass']);
   			return true;
  		}
 	}
 	
 	public function connected() {
  		if($this->socket) return true;
  		return false;
 	}
 
 	private function command($service,$command) {
  		if(!@fputs($this->socket,$this->numeric." ".$service." ".$command."\n")) {
   			return false;
  		} else {
   			$recive=true;
   			$data='';
   			while($recive) {
    			$data.=@fgets($this->socket);
			
    			$exp=explode("\n",$data);
    			for($i=0;$i<count($exp);$i++) {
    				$exp[$i]=str_replace("\r","",$exp[$i]);
     				$expb=explode(" ",$exp[$i]);
     				if($expb[0] == $this->numeric && $expb[1] == "E") {
      					$recive=false;
     				}
    			}
   			}
   			return $data;
  		}
	}
	
	function whoisNick($nick) {
		$data=$this->command("OpServ","whois ".$nick);
	  	$b=0;
	  	$exp=explode("\n",$data);
	  	$users="";
	  	for($i=0;$i<count($exp);$i++) {
	   		$expb=explode(" ",$exp[$i]);
	   		$expc=explode(":",$exp[$i],3);
	   		$expd=explode(" ",$expc[1]);
	  		if($expd[2] == "nick") {
	    		$uinfo['exists']=false;
	    		return $uinfo;
	   		} else {
	    		$uinfo['exists']=true;
	    		if($expd[0] == "Host") {
	     			$uinfo['host']=substr($expc[2],1);
	    		}
	    		if($expd[0] == "Fakehost") {
	     			$uinfo['fakehost']=substr($expc[2],1);
	    		}
	    		if($expd[0] == "Real") {
	     			$uinfo['ip']=substr($expc[2],1);
	    		}
	    		if($expd[0] == "Modes") {
	     			$uinfo['modes']=substr($expc[2],1);
	    		}
	    		if($expd[0] == "Info") {
	     			$uinfo['info']=substr($expc[2],1);
	    		}
	    		if($expd[0] == "Server") {
	     			$uinfo['server']=substr($expc[2],1);
	    		}
	    		if($expd[0] == "Account") {
	     			$uinfo['auth']=substr($expc[2],1);
	    		}
	    		if($expd[0] == "Channels") {
	     			if($uinfo['channel'] != "") $uinfo['channel'].=" ";
	     			$uinfo['channel'].=substr($expc[2],1);
	    		}
	   		}
	  	}
	  	return $uinfo;
	}
	
 	public function setUserSetting($user,$setting,$value) {
  		$data=$this->command("AuthServ","OSET *".$user." ".$setting." ".$value);
  		$b=0;
  		$exp=explode("\n",$data);
  		$users="";
  		for($i=0;$i<count($exp);$i++) {
   			$expb=explode(" ",$exp[$i]);
   			$expc=explode(":",$exp[$i],2);
			if(array_key_exists(1, $expc)) {
   				if($expc[1][0] == "") {
    					$expd=explode("",$expc[1]);
    					return $expd[2];
				}
   			}
  		}
  		return false;
 	}

	public function getUserSetting($user, $setting) {
		$data=$this->command("AuthServ","OSET *".$user." ".$setting);
		$exp=explode("\n",$data);
		for($i=0;$i<count($exp);$i++) {
			$expb=explode(" ",$exp[$i]);
   			$expc=explode(":",$exp[$i],2);
			if(array_key_exists(1, $expc)) {
				$expd=explode(":",$expc[1]);
				foreach($expd AS $expdKey=>$expdValue) {
					$expd[$expdKey] = trim(preg_replace("/[^a-zA-Z0-9\ \.\-\@\:\_]/","",$expd[$expdKey]));
				}
				if(array_key_exists(1, $expd)) {
					return $expd[1];
				}
			}
		}
	}
 	
 	public function login($user, $password) {
 		$data = $this->command('AuthServ', 'CHECKPASS ' . $user . ' ' . $password);
 		$exp=explode("\n",$data);
		for($i=0;$i<count($exp);$i++) {
			$expb=explode(" ",$exp[$i]);
   			$expc=explode(":",$exp[$i],2);
			if(array_key_exists(1, $expc)) {
				$valid = (str_replace('.', '', $expc[1]) == 'Yes') ? true : false;
				return $valid;
			}
		}
 	}

	public function searchAccount($accountMask) {
		$data = $this->command('AuthServ', 'search print accountmask ' . $accountMask);
 		$exp=explode("\n",$data);
		$accounts = array();
		for($i=0;$i<count($exp);$i++) {
			$expb=explode(" ",$exp[$i]);
   			$expc=explode(":",$exp[$i],2);
			if(array_key_exists(1, $expc)) {
				$expd=explode(":",$expc[1]);
				foreach($expd AS $expdKey=>$expdValue) {
					$expd[$expdKey] = trim(preg_replace("/[^a-zA-Z0-9\ \.\-\@\:\_]/","",$expd[$expdKey]));
				}
				if(array_key_exists(1, $expd)) {
					if($expd[0] == 'Match') {
						$accounts[] = $expd[1];
					}
				}
			}
		}
		return $accounts;
	}
	
	public function getAccountID($account) {
		$data = $this->command('AuthServ', 'findid ' . StringUtil::trim($account));
		$exp=explode("\n",$data);
		for($i=0;$i<count($exp);$i++) {
			$expb=explode(" ",$exp[$i]);
			if(array_key_exists(6, $expb)) {
				return StringUtil::trim($expb[6]);
			}
		}
		return null;
	}
	
	public function getAccount($accountID) {
		$data = $this->command('AuthServ', 'search print id =' . intval($accountID));
 		$exp=explode("\n",$data);
		$account = null;
		for($i=0;$i<count($exp);$i++) {
			$expb=explode(" ",$exp[$i]);
   			$expc=explode(":",$exp[$i],2);
			if(array_key_exists(1, $expc)) {
				$expd=explode(":",$expc[1]);
				foreach($expd AS $expdKey=>$expdValue) {
					$expd[$expdKey] = trim(preg_replace("/[^a-zA-Z0-9\ \.\-\@\:\_]/","",$expd[$expdKey]));
				}
				if(array_key_exists(1, $expd)) {
					if($expd[0] == 'Match') {
						return $expd[1];
					}
				}
			}
		}
		return null;
	}

	public function listDevnull() {
		$data = $this->command('OpServ', 'devnull list');
 		$exp=explode("\n",$data);
		$devnull = array();
		for($i=0;$i<count($exp);$i++) {
			$expb=explode(" ",$exp[$i]);
   			$expc=explode(":",$exp[$i],2);
			if(array_key_exists(1, $expc)) {
				if($expc[1] != '-') {
				$expd = explode(" ",$expc[1]);
				$expe = array();
				foreach($expd AS $key=>$value) {
					if($value != '') {
						$expe[] = $value;
					}
				}

				if($expe[0] != 'Name') {
					$devnull[] = array(
						'name' => $expe[0],
						'mc' => $expe[1],
						'ut' => $expe[2],
						'fl' => $expe[3],
						'ch' => $expe[4],
						'ih' => $expe[5],
						'si' => $expe[6],
						'ih2' => $expe[7],
						'oc' => $expe[8],
						'om' => $expe[9],
						'k' => $expe[10],
						's' => $expe[11],
						'x' => $expe[12],
						'maxq' => $expe[13],
						'opme' => $expe[14],
					);
				}
				
				} else {
					return $devnull;
				}
			}
		}
	}
	
	public function getChannel() {
		$data = $this->command('OpServ', 'csearch print name *');
 		$exp=explode("\n",$data);
		$channel = array();
		for($i=0;$i<count($exp);$i++) {
			$expb=explode(" ",$exp[$i]);
   			$expc=explode(":",$exp[$i],2);
			if(array_key_exists(1, $expc)) {
				if(substr($expc[1], 0, strlen('#')) === '#') {
					$expd=explode(" ",$expc[1]);
					if((strpos($expd[3],'s')!==false) || (strpos($expd[3],'p')!==false)) {
						continue;
					}
					$channel[str_replace('#', '', $expd[0])]['name'] = str_replace('#', '', $expd[0]);
				}
			}
		}
		return $channel;
	}

	public function getUser() {
		$channel = $this->getChannel();
		$n=-1;
		foreach($channel AS $channelItem) {
			$data = $this->command('OpServ', 'chaninfo #'.$channelItem['name']);
			$exp=explode("\n",$data);
			for($i=0;$i<count($exp);$i++) {
				$n++;
				$expb=explode(" ",$exp[$i]);
   				$expc=explode(":",$exp[$i],2);
				if(array_key_exists(1, $expc)) {
					$expd=explode(" ",$expc[1]);
					foreach($expd as $key => $value) {
						if($value == '') {
							unset($expd[$key]);
						}
					}
					$expe = array_values($expd);
					if($n<=5) {
						continue;
					}
					if(substr($expe[0], 0, strlen('#')) === '#') {
						$n=1;
						continue;
					}
					if(!array_key_exists('user', $channel[$channelItem['name']])) {
						$channel[$channelItem['name']]['user'] = array();
					}
					$expf = explode(':', $expe[0]);
					$channel[$channelItem['name']]['user'][] = $expf[0];
				}
			}
		}
		return $channel;
	}

	public function addUser($username, $password, $email) {
		$data = array();
		$data[] = $this->command('AuthServ', 'oregister '.$username.' '.$password.' *@*');
		$data[] = $this->command('AuthServ', 'oset *'.$username.' email '.$email);

		return $data;
	}
	
	public function deleteUser($username) {
		return $this->command('AuthServ', 'ounregister *'.$username.' FORCE');
	}
	
	public function resetPassword($username, $password) {
		$data = $this->command('AuthServ', 'oset *'.$username.' pass '.$password);
		$exp=explode("\n",$data);
		for($i=0;$i<count($exp);$i++) {
			$expb=explode(":",$exp[$i],2);
			if(array_key_exists(1, $expb)) {
				if(strpos($expb[1],"has not been")!==false) {
					$int = rand(1,100);
					$mail = 'dummy'.$int.'@irc.local';
					return $this->adduser($username,$password,$mail);
				}
				if(strpos($expb[1],"PASSWORD")!==false) {
					return true;
				}
			}
		}
		return false;
	}
	
	public function renameAccount($username, $newUsername) {
		return $this->command('AuthServ', 'rename *'.$username.' '.$newUsername);
	}
	
	public function setEmail($username, $email) {
		return $this->command('AuthServ', 'oset *'.$username.' email '.$email);
	}
	
	public function sendMessageToTarget($user, $target, $message) {
		return $this->command('OpServ', 'simul '.$user.' privmsg :'.$target.' '.$message);
	}
	
	public function sendNoticeToTarget($user, $target, $message) {
		$this->command('OpServ', 'simul '.$user.' notice :'.$target.' '.$message);
	}
}
?>