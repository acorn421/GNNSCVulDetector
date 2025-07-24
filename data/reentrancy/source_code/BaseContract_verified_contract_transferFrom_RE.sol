/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before updating the allowance. The external call enables the recipient contract to re-enter transferFrom while the allowance is still unchanged, creating a window for exploitation across multiple transactions. The vulnerability requires:
 * 
 * 1. **Transaction 1**: Attacker calls transferFrom, triggering the callback where their malicious contract can call approve() to reset the allowance or call transferFrom again before the allowance is decremented
 * 2. **Transaction 2+**: Attacker can repeat the process, exploiting the persistent allowance state that was manipulated in previous transactions
 * 
 * The vulnerability is stateful because:
 * - The allowance mapping persists between transactions
 * - Balance changes from previous transactions affect subsequent exploitation
 * - The attack requires coordination across multiple transactions to be effective
 * - The vulnerability window exists across multiple blocks due to persistent state
 * 
 * This creates a realistic attack scenario where an attacker can drain funds by exploiting the timing between balance updates and allowance decrements across multiple transactions.
 */
pragma solidity ^0.4.24;

contract CFG {
	event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Consume(address indexed from, uint256 value);
}

contract BaseContract is CFG{
    using SafeMath for uint256;
    
    string public name = "Cyclic Finance Game";
    string public symbol = "CFG";
    uint8 public decimals = 18;
    uint256 public totalSupply = 81000000000000000000000000;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    address public cfgContractAddress;
    
    constructor() public {
        balanceOf[msg.sender] = totalSupply;
    }
    
    function transfer(address _to, uint256 _value) public returns (bool success){
    	require(_to != 0x0, "invalid addr");
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_spender != 0x0, "invalid addr");
		require(_value > 0, "invalid value");
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender,_spender,_value);
        return true;
    }
    
     function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
    	require(_from != 0x0, "invalid addr");
        require(_to != 0x0, "invalid addr");
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABLE: External call before allowance update - enables reentrancy
        uint size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            require(_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", _from, _value)), "callback failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }
     
     function consume(address _from,uint256 _value) public returns (bool success){
    	require(msg.sender == cfgContractAddress, "invalid addr");
    	balanceOf[_from] = balanceOf[_from].sub(_value);
//   	totalSupply = totalSupply.sub(_value);
    	emit Consume(_from, _value);
    	return true;
     }
     
     function setCfgContractAddress(address _cfgContractAddress) public returns (bool success){
    	require(cfgContractAddress == address(0), "invalid addr");
    	cfgContractAddress = _cfgContractAddress;
    	return true;
     }
    
}

library SafeMath {

	function sub(uint256 a, uint256 b)
	internal
	pure
	returns(uint256 c) {
		require(b <= a, "sub failed");
		c = a - b;
		require(c <= a, "sub failed");
		return c;
	}

	function add(uint256 a, uint256 b)
	internal
	pure
	returns(uint256 c) {
		c = a + b;
		require(c >= a, "add failed");
		return c;
	}

}
