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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: Attacker sets up a malicious contract and gets approval for token transfers
 * 2. **Transaction 2**: Attacker calls transferFrom, which triggers the external call to onTokenReceived()
 * 3. **During Transaction 2**: The malicious contract can reenter transferFrom before balances are updated, allowing double-spending of the same allowance
 * 
 * The vulnerability is stateful because:
 * - It relies on previously approved allowances from Transaction 1
 * - The inconsistent state during the external call (balances not yet updated) persists across the call stack
 * - Each reentrant call can consume the same allowance amount before it's decremented
 * 
 * This follows the classic Checks-Effects-Interactions pattern violation, where the external call (Interaction) happens before the state updates (Effects), creating a window for reentrancy exploitation that spans multiple transactions and depends on accumulated state.
 */
pragma solidity ^0.4.13;
 
contract TokenReceiver {
    function onTokenReceived(address _from, uint256 _amount) public;
}

contract Dexer {
    string public symbol = "DEX";
    string public name = " Dexer ";
    uint8 public constant decimals = 2;
    uint256 _totalSupply = 300000000;
    address owner = 0x35a887e7327cb08e7a510D71a873b09d5055709D;
    bool setupDone = false;
	
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
 
    mapping(address => uint256) balances;
 
    mapping(address => mapping (address => uint256)) allowed;
 
    function Token(address adr) public {
		owner = adr;        
    }
	
	function SetupToken(string tokenName, string tokenSymbol, uint256 tokenSupply) public
	{
		if (msg.sender == owner && setupDone == false)
		{
			symbol = tokenSymbol;
			name = tokenName;
			_totalSupply = tokenSupply * 100;
			balances[owner] = _totalSupply;
			setupDone = true;
		}
	}
 
    function totalSupply() public constant returns (uint256) {        
		return _totalSupply;
    }
 
    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }
 
    function transfer(address _to, uint256 _amount) public returns (bool success) {
        if (balances[msg.sender] >= _amount 
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }
 
    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) public returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // External call to recipient contract for transfer notification
            // This enables reentrancy before state updates
            if (isContract(_to)) {
                TokenReceiver(_to).onTokenReceived(_from, _amount);
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }
 
    function approve(address _spender, uint256 _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }
 
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
