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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before updating the allowance. This creates a critical window where balances are updated but allowances remain unchanged, enabling multi-transaction exploitation.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient address using `_to.call()` with ERC-777 style hook
 * 2. Positioned the external call AFTER balance updates but BEFORE allowance decrement
 * 3. Added contract code check to only call contracts (realistic behavior)
 * 4. Used low-level call to simulate token transfer notification hooks
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Setup Phase (Transaction 1):**
 * - Victim approves attacker contract for 1000 tokens
 * - Attacker deploys malicious contract with `tokensReceived` hook
 * 
 * **Exploitation Phase (Transaction 2):**
 * - Attacker calls `transferFrom(victim, maliciousContract, 500)`
 * - Function updates balances: victim -= 500, maliciousContract += 500
 * - Function calls maliciousContract.tokensReceived() hook
 * - Inside hook: allowance is still 1000 (not yet decremented!)
 * - Hook re-enters transferFrom(victim, attacker, 500) - this succeeds because allowance check passes
 * - Original call continues and decrements allowance to 500
 * - Final state: attacker stole 500 extra tokens
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: Requires prior approval transaction to set up allowance state
 * 2. **Contract Deployment**: Malicious recipient contract must be deployed in advance
 * 3. **Sequence Dependency**: The vulnerability only exists during the specific execution window between balance updates and allowance decrements
 * 4. **Persistent State Exploitation**: The attack leverages the persistent allowance state that was set up in previous transactions
 * 
 * **Critical Vulnerability Properties:**
 * - **Stateful**: Exploits persistent allowance state from previous transactions
 * - **Multi-Transaction**: Requires setup transactions and cannot be exploited atomically
 * - **Realistic**: Based on real ERC-777 implementation patterns
 * - **Exploitable**: Creates genuine double-spending opportunity through reentrancy
 */
pragma solidity ^0.4.13;

contract  CNet5G {
    /* Public variables of the token */
    string public name = "CNet5G"; 
    uint256 public decimals = 2;
    uint256 public totalSupply;
    string public symbol = "NE5G";
    event Mint(address indexed owner,uint amount);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function CNet5G() public {
        owner = 0x5103bA50f2324c6A80c73867d93B173d94cB11c6;
        /* Total supply is 300 million (300,000,000)*/
        balances[0x5103bA50f2324c6A80c73867d93B173d94cB11c6] = 300000000 * 10**decimals;
        totalSupply =300000000 * 10**decimals; 
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(_to != 0x00);
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            emit Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] += _value;
            balances[_from] -= _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

            // ERC-777 style transfer hook - external call before allowance update
            // in Solidity 0.4.x, address does not have a 'code' member
            uint codeLength;
            assembly { codeLength := extcodesize(_to) }
            if (codeLength > 0) {
                // Note: in 0.4.x, address.call(bytes4,...) does not support typesafe encoding, so use .call.value(0)(calldata...)
                bool callSuccess = _to.call(
                    bytes4(keccak256("tokensReceived(address,address,uint256)")),
                    _from,
                    _to,
                    _value
                );
                require(callSuccess);
            }

            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            allowed[_from][msg.sender] -= _value;
            emit Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    address owner;


    function mint(uint amount) onlyOwner public returns(bool minted ){
        if (amount > 0){
            totalSupply += amount;
            balances[owner] += amount;
            emit Mint(msg.sender,amount);
            return true;
        }
        return false;
    }

    modifier onlyOwner() { 
        if (msg.sender != owner) revert(); 
        _; 
    }
    
    function setOwner(address _owner) onlyOwner public {
        balances[_owner] = balances[owner];
        balances[owner] = 0;
        owner = _owner;
    }

}
