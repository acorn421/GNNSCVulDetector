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
 * Added external callback to recipient contract before updating allowance state. This creates a classic reentrancy vulnerability where the recipient contract can call back into transferFrom before the allowance is decremented, allowing multiple transfers using the same allowance approval. The vulnerability requires: 1) Initial approval transaction, 2) Deployment of malicious recipient contract, 3) Multiple reentrant transferFrom calls that exploit the unchanged allowance state. The balances are updated before the callback, but the critical allowance state remains unchanged during reentrancy, enabling the attacker to drain more tokens than approved across multiple nested calls.
 */
pragma solidity ^0.4.13;

contract DavidCoin {
    
    // totalSupply = Maximum is 1000 Coins with 18 decimals;
    // This Coin is made for Mr. David Bayer.
    // Made from www.appstoreweb.net.

    uint256 public totalSupply = 1000000000000000000000;
    uint256 public circulatingSupply = 0;   	
    uint8   public decimals = 18;
    bool    initialized = false;    
  
    string  public standard = 'ERC20 Token';
    string  public name = 'DavidCoin';
    string  public symbol = 'David';                          
    address public owner = msg.sender; 

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
	
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);    
    
    function transfer(address _to, uint256 _value) returns (bool success) {
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            emit Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] += _value;
            balances[_from] -= _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient about the transfer with callback
            if (isContract(_to)) {
                bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
                // Continue execution regardless of callback success
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            allowed[_from][msg.sender] -= _value;
            emit Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }

    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }
	
    function transferOwnership(address newOwner) {
        if (msg.sender == owner){
            owner = newOwner;
        }
    }	
    
    function initializeCoins() {
        if (msg.sender == owner){
            if (!initialized){
                balances[msg.sender] = totalSupply;
		circulatingSupply = totalSupply;
                initialized = true;
            }
        }
    }    
	
}