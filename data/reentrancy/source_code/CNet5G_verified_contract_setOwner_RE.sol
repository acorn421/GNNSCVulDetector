/*
 * ===== SmartInject Injection Details =====
 * Function      : setOwner
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
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the new owner before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Phase 1 (Transaction 1):** Attacker calls setOwner() with a malicious contract address, which triggers the external call to onOwnershipTransfer(). During this call, the contract is in an intermediate state where pendingOwner is set but the actual ownership transfer hasn't completed yet.
 * 
 * **Phase 2 (Reentrancy):** The malicious contract's onOwnershipTransfer() function can reenter the contract during the external call. At this point, transferInProgress is true, and the attacker can call other functions that might behave differently due to the intermediate state.
 * 
 * **Phase 3 (Transaction 2):** After the initial transaction completes, the attacker can leverage the state changes from the first transaction to perform additional attacks in subsequent transactions, potentially exploiting the fact that balances were transferred but other contract functions might not account for the ownership change properly.
 * 
 * The vulnerability is stateful because it depends on the transferInProgress flag and pendingOwner state variables that persist between transactions. It's multi-transaction because the full exploit requires the attacker to first trigger the ownership transfer (setting up the intermediate state) and then leverage that state in subsequent calls or reentrancy attempts.
 * 
 * **Required State Variables to Add:**
 * - `bool transferInProgress;`
 * - `address pendingOwner;`
 * 
 * **Exploitation Sequence:**
 * 1. **Transaction 1:** Attacker calls setOwner() with malicious contract
 * 2. **Reentrancy:** During external call, attacker reenters and exploits intermediate state
 * 3. **Transaction 2:** Attacker leverages the modified state from previous transactions to perform additional attacks
 * 
 * This creates a realistic multi-transaction vulnerability where the attacker must accumulate state changes across multiple calls to achieve full exploitation.
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

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    address owner;

    // Added missing state variables for ownership transfer logic
    address public pendingOwner;
    bool public transferInProgress;

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
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }

    function mint(uint amount) onlyOwner public returns(bool minted ){
        if (amount > 0){
            totalSupply += amount;
            balances[owner] += amount;
            Mint(msg.sender,amount);
            return true;
        }
        return false;
    }

    modifier onlyOwner() { 
        if (msg.sender != owner) revert(); 
        _; 
    }
    
    function setOwner(address _owner) onlyOwner public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Phase 1: Initiate ownership transfer with external notification
        pendingOwner = _owner;
        transferInProgress = true;
        
        // External call to notify new owner - creates reentrancy opportunity
        bool success = _owner.call(bytes4(keccak256("onOwnershipTransfer(address,uint256)")), owner, balances[owner]);
        
        if (success) {
            // Critical state changes occur after external call
            balances[_owner] = balances[owner];
            balances[owner] = 0;
            owner = _owner;
            transferInProgress = false;
            delete pendingOwner;
        } else {
            // Reset state if notification fails
            transferInProgress = false;
            delete pendingOwner;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

}
