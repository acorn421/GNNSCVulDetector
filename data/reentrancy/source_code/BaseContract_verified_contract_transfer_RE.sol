/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a callback mechanism that allows recipient contracts to receive notifications after balance updates but before the Transfer event. This creates a reentrancy vulnerability where the recipient contract can call back into the token contract during the callback, potentially exploiting the already-updated state in subsequent transactions. The vulnerability requires multiple transactions: (1) initial transfer with callback setup, (2) callback execution that can manipulate state, and (3) exploitation of the accumulated state changes. The callback occurs after critical state updates (balanceOf modifications) but before the Transfer event emission, creating a window for reentrancy attacks that depend on the persistent state changes from previous transactions.
 */
pragma solidity ^0.4.24;

contract CFG {
	event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Consume(address indexed from, uint256 value);
}

interface ITokenReceiver {
    function onTokenReceived(address from, uint256 value) external returns (bool);
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
        require(_to != address(0), "invalid addr");
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient if it's a contract (callback mechanism)
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // External call to potentially malicious contract
            ITokenReceiver(_to).onTokenReceived(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_spender != address(0), "invalid addr");
        require(_value > 0, "invalid value");
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender,_spender,_value);
        return true;
    }
    
     function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_from != address(0), "invalid addr");
        require(_to != address(0), "invalid addr");
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }
     
     function consume(address _from,uint256 _value) public returns (bool success){
        require(msg.sender == cfgContractAddress, "invalid addr");
        balanceOf[_from] = balanceOf[_from].sub(_value);
//    totalSupply = totalSupply.sub(_value);
        emit Consume(_from, _value);
        return true;
     }
     
     function setCfgContractAddress(address _cfgContractAddress) public returns (bool success){
        require(cfgContractAddress == address(0), "invalid addr");
        cfgContractAddress = _cfgContractAddress;
        return true;
     }
    
}
