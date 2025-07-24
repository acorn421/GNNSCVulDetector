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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the recipient contract before the allowance is decremented. This creates a window where the attacker can re-enter the function multiple times across different transactions with the same allowance, enabling token draining beyond the approved amount. The vulnerability requires: (1) Initial approval transaction to set allowance, (2) Deployment of malicious receiver contract, (3) Multiple transferFrom calls that trigger reentrancy during the callback, exploiting the fact that allowance is decremented after the external call.
 */
pragma solidity ^0.4.11;
contract OrpheusBlockChainCitySiam {
    
    uint public constant _totalSupply = 300000000000000000000000000;
    
    string public constant symbol = "OBCS";
    string public constant name = "Orpheus Block Chain City Siam";
    uint8 public constant decimals = 18;
    
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;
    
    function OrpheusBlockChainCitySiam() public {
        balances[msg.sender] = _totalSupply;
    }
    
    function totalSupply() public constant returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner]; 
    }
    
    function transfer (address _to, uint256 _value) public returns (bool success) {
        require(
            balances[msg.sender] >= _value
            && _value > 0 
        );
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(
            allowed[_from][msg.sender] >= _value
            && balances[_from] >= _value
            && _value > 0 
        );
        balances[_from] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract of token transfer (ERC777-style callback)
        if (isContract(_to)) {
            ITokenReceiver(_to).tokensReceived(_from, _to, _value, msg.sender);
        }
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value); 

    // Helper function to identify contract addresses
    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}

// Declare the ITokenReceiver interface used in transferFrom for the callback
interface ITokenReceiver {
    function tokensReceived(address from, address to, uint256 value, address sender) external;
}