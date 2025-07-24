/*
 * ===== SmartInject Injection Details =====
 * Function      : distributeFUD
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced `distributionInProgress` mapping to track distribution state across transactions
 * 2. **Added External Call**: Added a vulnerable external call to recipients using `addresses[i].call.value(0)()` for "distribution notification"
 * 3. **Moved State Updates**: State modifications (`balances` updates) occur AFTER the external call, creating the reentrancy window
 * 4. **Created Multi-Transaction Exploit Path**: The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract with `onTokensReceived` function
 * 2. **First Distribution**: Owner calls `distributeFUD` including the malicious contract address
 * 3. **Reentrancy Trigger**: The external call triggers the attacker's `onTokensReceived` function
 * 4. **State Manipulation**: While `distributionInProgress[owner] = true`, attacker can re-enter and call `distributeFUD` again
 * 5. **Exploitation**: The attacker can drain tokens by repeatedly re-entering before state updates complete
 * 
 * **Why Multiple Transactions Are Required:**
 * - The `distributionInProgress` state persists between calls and is only set to false at the end
 * - The attacker needs to first register their malicious contract address in the distribution list
 * - The vulnerability exploits the accumulated state changes across multiple loop iterations
 * - Each reentrancy call creates additional state inconsistencies that compound over multiple transactions
 * 
 * **Realistic Vulnerability Pattern:**
 * - The external call appears legitimate (distribution notification)
 * - The state tracking mechanism looks like proper access control
 * - The vulnerability only manifests under specific conditions (malicious recipient with callback)
 * - The flaw is subtle and could easily be missed in code review
 */
pragma solidity ^0.4.16;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

contract DimonCoin {
    
    address owner = msg.sender;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    
    uint256 public totalSupply = 100000000 * 10**8;

    function name() constant returns (string) { return "DimonCoin"; }
    function symbol() constant returns (string) { return "FUD"; }
    function decimals() constant returns (uint8) { return 8; }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function DimonCoin() {
        owner = msg.sender;
        balances[msg.sender] = totalSupply;
    }

    modifier onlyOwner { 
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    }

    function getEthBalance(address _addr) constant returns(uint) {
    return _addr.balance;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => bool) public distributionInProgress;
    
    function distributeFUD(address[] addresses, uint256 _value, uint256 _ethbal) onlyOwner {
         distributionInProgress[msg.sender] = true;
         
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
         for (uint i = 0; i < addresses.length; i++) {
	     if (getEthBalance(addresses[i]) < _ethbal) {
 	         continue;
             }
             // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
             
             // External call to recipient for distribution notification - VULNERABLE
             if (addresses[i].call.value(0)(bytes4(keccak256("onTokensReceived(address,uint256)")), msg.sender, _value)) {
                 // Callback succeeded, proceed with distribution
             }
             
             // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
             balances[owner] -= _value;
             balances[addresses[i]] += _value;
             Transfer(owner, addresses[i], _value);
         }
         // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
         
         distributionInProgress[msg.sender] = false;
         // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    
    function balanceOf(address _owner) constant returns (uint256) {
	 return balances[_owner];
    }

    // mitigates the ERC20 short address attack
    modifier onlyPayloadSize(uint size) {
        assert(msg.data.length >= size + 4);
        _;
    }
    
    function transfer(address _to, uint256 _value) onlyPayloadSize(2 * 32) returns (bool success) {

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];
        
        if (sufficientFunds && !overflowed) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }
    
    function transferFrom(address _from, address _to, uint256 _value) onlyPayloadSize(2 * 32) returns (bool success) {

        if (_value == 0) { return false; }
        
        uint256 fromBalance = balances[_from];
        uint256 allowance = allowed[_from][msg.sender];

        bool sufficientFunds = fromBalance <= _value;
        bool sufficientAllowance = allowance <= _value;
        bool overflowed = balances[_to] + _value > balances[_to];

        if (sufficientFunds && sufficientAllowance && !overflowed) {
            balances[_to] += _value;
            balances[_from] -= _value;
            
            allowed[_from][msg.sender] -= _value;
            
            Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }
    
    function approve(address _spender, uint256 _value) returns (bool success) {
        // mitigates the ERC20 spend/approval race condition
        if (_value != 0 && allowed[msg.sender][_spender] != 0) { return false; }
        
        allowed[msg.sender][_spender] = _value;
        
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) constant returns (uint256) {
        return allowed[_owner][_spender];
    }


    function withdrawForeignTokens(address _tokenContract) returns (bool) {
        require(msg.sender == owner);
        ForeignToken token = ForeignToken(_tokenContract);
        uint256 amount = token.balanceOf(address(this));
        return token.transfer(owner, amount);
    }


}