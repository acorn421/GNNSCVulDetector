/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the user's contract before state updates. This violates the Checks-Effects-Interactions (CEI) pattern and creates a window for reentrancy attacks that require multiple coordinated transactions to exploit effectively.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `msg.sender.call()` with `onBurn(uint256)` callback before state modifications
 * 2. The callback occurs after the balance check but before the actual balance and totalSupply updates
 * 3. Used low-level `call()` to make the external interaction more realistic and dangerous
 * 4. Added a check for contract code existence to make the callback conditional on the caller being a contract
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):** 
 * - Attacker deploys a malicious contract that implements the `onBurn` callback
 * - The contract holds some legitimate tokens to pass the initial balance check
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `burn()` from their malicious contract
 * - The `onBurn` callback is triggered before state updates
 * - Inside the callback, the attacker can re-enter `burn()` multiple times
 * - Each reentrant call sees the same unchanged balance (state hasn't been updated yet)
 * - This allows burning more tokens than actually owned
 * 
 * **Transaction 3 (Exploitation Continuation):**
 * - After the initial exploitation, the attacker can continue to manipulate the inconsistent state
 * - Subsequent calls can exploit the accumulated state changes from previous transactions
 * - The persistent state corruption enables further exploitation across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The vulnerability relies on accumulated state changes across transactions
 * 2. **Coordination Requirement**: The attack requires coordinated setup (malicious contract deployment) and execution
 * 3. **Persistent State Corruption**: The exploit creates persistent state inconsistencies that enable further exploitation
 * 4. **Cross-Transaction Dependencies**: Each transaction builds upon the state changes from previous transactions
 * 
 * This creates a realistic, stateful vulnerability that mirrors real-world reentrancy attacks seen in production token contracts.
 */
pragma solidity ^0.4.16;

contract RETHToken {

    string public name;
    string public symbol;
    uint8 public decimals = 18;

    uint256 public totalSupply;


    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;


    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    function RETHToken() public {
        totalSupply = 400000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "RETH Token";
        symbol = "RETH";
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }
     
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
     
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }
     
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // INJECTED: External callback before state updates (violates CEI pattern)
        // This creates a stateful reentrancy vulnerability
        address candidate = msg.sender;
        uint size;
        assembly { size := extcodesize(candidate) }
        if (size > 0) {
            candidate.call(bytes4(keccak256("onBurn(uint256)")), _value);
            // Continue execution even if callback fails
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                      
        Burn(msg.sender, _value);
        return true;
    }
     
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        Burn(_from, _value);
        return true;
    }
}
