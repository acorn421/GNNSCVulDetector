/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This creates a window where the recipient can re-enter the transfer function with outdated balance state, enabling cross-transaction exploitation patterns.
 * 
 * **Specific Changes Made:**
 * 1. **External Call Injection**: Added a low-level call to `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _amount))` that executes BEFORE state updates
 * 2. **Contract Detection**: Added `_to.code.length > 0` check to only call contracts (realistic optimization)
 * 3. **Vulnerability Window**: The external call occurs after balance validation but before balance updates, creating a reentrancy window
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract with `onTokenReceived` callback
 * - Attacker calls `transfer` to their malicious contract with amount X
 * - During the external call, malicious contract can:
 *   - View current balances (sender still has full balance)
 *   - Prepare attack state for next transaction
 *   - Cannot fully exploit in same transaction due to gas limits and call depth
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `transfer` again with amount Y
 * - The external call in transaction 2 triggers the malicious callback
 * - Malicious contract can now:
 *   - Re-enter `transfer` with knowledge of previous incomplete state
 *   - Exploit the fact that sender's balance from transaction 1 may not be fully committed
 *   - Potentially drain more tokens than should be possible
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: Balances are stored in persistent storage, creating state dependencies across transactions
 * 2. **Gas Limitations**: Complex reentrancy attacks require multiple transactions to avoid gas limit issues
 * 3. **Call Depth Protection**: Solidity's call depth limit prevents infinite recursion in single transaction
 * 4. **Stateful Attack Setup**: The attacker needs to establish attack state in one transaction and exploit it in another
 * 5. **Balance Verification Bypass**: The vulnerability allows circumventing balance checks across transaction boundaries
 * 
 * **Exploitation Scenario:**
 * - Attacker with 100 tokens can potentially transfer 200+ tokens across multiple transactions
 * - Each transaction passes individual balance checks but collectively violate system invariants
 * - The external call provides the necessary hook for cross-transaction state manipulation
 */
pragma solidity ^0.4.11;
 
contract OnePieceGold {
    string public symbol = "";
    string public name = "";
    uint8 public constant decimals = 18;
    uint256 _totalSupply = 0;
    address owner = 0;
    bool setupDone = false;
	
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
 
    mapping(address => uint256) balances;
 
    mapping(address => mapping (address => uint256)) allowed;
 
    function OnePieceGold(address adr) public {
		owner = adr;        
    }
	
	function SetupToken(string tokenName, string tokenSymbol, uint256 tokenSupply) public
	{
		if (msg.sender == owner && setupDone == false)
		{
			symbol = tokenSymbol;
			name = tokenName;
			_totalSupply = tokenSupply * 1000000000000000000;
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient before state update - creates reentrancy window
            if (isContract(_to)) {
                // Using low-level call preserves the bug for reentrancy.
                _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _amount));
                // Continue regardless of callback success
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    // Helper function to check if address is a contract (Solidity 0.4.x)
    function isContract(address addr) internal constant returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
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
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
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