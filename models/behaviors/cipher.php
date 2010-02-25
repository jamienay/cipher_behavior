<?php
/**
 * Cipher Behavior class file.
 *
 * Encrypts and decrypts data using Zend_Filter_Encrypt and Zend_Filter_Decrypt, which in turn
 * uses the blowfish algorithm.
 *
 * ****************** ZEND LIBRARY SETUP ****************** 
 * 
 * This behavior requires the following Zend Framework libaries:
 * - Zend_Filter (Zend/Filter.php and Zend/Filter)
 * - Zend_Loader (Zend/Loader.php and Zend/Loader)
 * 
 * Put those files in your vendors folder. You'll also need to update your include_path 
 * somewhere with the following:
 * 
 * ini_set('include_path', ini_get('include_path') . ':' . APP . '/vendors'); 
 * 
 * I also recommend defining an autoload function somewhere for Zend classes:
 *
 * function __autoload($path) {
 *	 if (substr($path, 0, 5) == 'Zend_') {
 *		include str_replace('_', '/', $path) . '.php';
 *	 }
 *	 return $path;
 * }
 *
 * ******************************************************** 
 * 
 * @filesource
 * @author			Jamie Nay
 * @copyright       Jamie Nay
 * @license			http://www.opensource.org/licenses/mit-license.php The MIT License
 * @link            http://jamienay.com/2010/02/cipher-behavior-with-zend_filter-for-cakephp-1-3-easy-two-way-encryption
 */
class CipherBehavior extends ModelBehavior {
	/**
	 * Behavior settings
	 * 
	 * @access public
	 * @var array
	 */
	public $settings = array();

	/**
	 * Default values for settings.
	 *
	 * key - the encryption key for the algorithm. Defaults to Security.salt
	 * automatic - whether to encrypt/decrypt info automatically
	 * fields - the encrypted fields for the model
	 *
	 * @access private
	 * @var array
	 */
    private $defaults = array(
    	'key' => null,
    	'automatic' => true,
    	'fields' => array('password')
    );

	/**
	 * Zend_Filter_Encrypt object instance
	 *
	 * @access public
	 * @var object
	 */
	public $encryptFilter = null;
	
	/**
	 * Zend_Filter_Decrypt object instance
	 *
	 * @access public
	 * @var object
	 */
	public $decryptFilter = null;
	
	/**
	 * Vector string for encryption/decryption.
	 * MUST BE 8 CHARACTERS!
	 *
	 * @access private
	 * @var string
	 */
	private $__vector = '80gf3zv7';
	
    /**
     * Configuration method.
     *
     * @param object $Model		Model object
     * @param array $config		Config array
     * @access public
     * @return boolean
     */
    public function setup($Model, $config = array()) {
    	$this->settings[$Model->alias] = array_merge($this->defaults, $config);
    	if (!$this->settings[$Model->alias]['key']) {
    		$this->settings[$Model->alias]['key'] = Configure::read('Security.salt');
    	}
    	
    	$this->encryptFilter = new Zend_Filter_Encrypt(array(
    		'key' => $this->settings[$Model->alias]['key'],
    		'adapter' => 'Mcrypt'
    	));
    	
    	$this->decryptFilter = new Zend_Filter_Decrypt(array(
    		'key' => $this->settings[$Model->alias]['key'],
    		'adapter' => 'Mcrypt'
    	));
    	
    	return true;
	}
	
	/**
	 * beforeSave
	 * Encrypt automatically if the automatic option is selected.
	 *
	 * @param object $Model		Model object
	 * @access public
	 * @return boolean
	 */
	public function beforeSave($Model) {
		if (!$this->settings[$Model->alias]['automatic']) {
			return true;
		}
		
		$this->encrypt($Model, $this->data);
		return true;
	}
	
	/**
	 * afterFind
	 * Decrypt automatically if the automatic option is selected.
	 *
	 * @param object $Model		Model object
	 * @param array	 $results	Find() query results
	 * @access public
	 * @return array
	 */
	public function afterFind($Model, $results) {
		if (!$this->settings[$Model->alias]['automatic']) {
			return $results;
		}
		
		if (isset($results[0])) {
			foreach ($results as $i => $result) {
				$results[$i] = $this->decrypt($Model, $result);
			}
		} else {
			$results = Set::extract($this->decrypt($Model, array($Model->alias => $results)), $Model->alias);
			
		}

		return $results;
	}
	
	/**
	 * encrypt
	 * Public encryption gateway method. Accepts either a single string 
	 * or an array of find() result data.
	 *
	 * @param object $Model		Model object
	 * @param mixed $data		Either a string or an array from find() results
	 * @access public
	 * @return mixed
	 */
	public function encrypt($Model, $data) {
		if (is_string($data)) {
			return $this->__encryptValue($data);
		}
		
		if (!$data) {
			$data = $Model->data;
		}

		foreach ($this->settings[$Model->alias]['fields'] as $field) {
			if (isset($data[$Model->alias][$field])) {
				$data[$Model->alias][$field] = $this->__encryptValue($data[$Model->alias][$field]);
			}
		}
		
		return $data;
	}
	
	/**
	 * decrypt
	 * Public decryption gateway method. Accepts either a single string 
	 * or an array of find() result data.
	 *
	 * @param object $Model		Model object
	 * @param mixed $data		Either a string or an array from find() results
	 * @access public
	 * @return mixed
	 */
	public function decrypt($Model, $data) {
		if (is_string($data)) {
			return $this->__decryptValue($data);
		}
		
		if (!$data) {
			$data = $Model->data;
		}

		foreach ($this->settings[$Model->alias]['fields'] as $field) {
			if (isset($data[$Model->alias][$field])) {
				$data[$Model->alias][$field] = $this->__decryptValue($data[$Model->alias][$field]);
			}
		}
		
		return $data;
	}
	
	/**
	 * __encryptValue
	 * Handles the actual encryption of data.
	 *
	 * @param string $data	Value to be encrypted
	 * @access private
	 * @return string
	 */
	private function __encryptValue($data) {
    	$filter = $this->encryptFilter;
		$filter->setVector($this->__vector);
		$encrypted = $filter->filter($data);
		return $encrypted;
	}
	
	/**
	 * __decryptValue
	 * Handles the actual decryption of data.
	 *
	 * @param string $data	Value to be decrypted
	 * @access private
	 * @return string
	 */
	private function __decryptValue($data) {
    	$filter = $this->decryptFilter;
		$filter->setVector($this->__vector);
		$encrypted = trim($filter->filter($data)); // trim() gets rid of extra characters in Firefox.
		return $encrypted;
	}
}
