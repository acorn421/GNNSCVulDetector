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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract (_to) before state updates. This creates a classic reentrancy attack vector where the recipient can call back into the contract during the transfer process, allowing manipulation of balances and allowances across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call()` with `onTokenReceived` callback
 * 2. Positioned the call after balance/allowance checks but before state updates (classic reentrancy pattern)
 * 3. Used low-level `call()` to ensure the external contract can execute arbitrary code
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys malicious contract that implements `onTokenReceived` callback
 * 2. **Transaction 2 (Trigger)**: Legitimate user calls `transferFrom` with attacker's contract as `_to`
 * 3. **During Callback**: Attacker's contract receives control and can:
 *    - Call `transferFrom` again with same parameters (state not yet updated)
 *    - Drain tokens by repeatedly calling before balances are decremented
 *    - Manipulate allowances before they're properly decremented
 * 4. **Transaction 3+ (Exploitation)**: Attacker continues exploitation across multiple calls
 * 
 * **Why Multi-Transaction Nature is Critical:**
 * - **State Persistence**: The vulnerability relies on allowances and balances persisting between transactions
 * - **Accumulated Effect**: Each successful reentrant call drains more tokens, requiring multiple calls to be profitable
 * - **Setup Requirement**: Attacker must first deploy malicious contract and get approved allowances
 * - **Sequential Dependency**: The exploit requires specific sequence of approvals, transfers, and callbacks across multiple blocks
 * 
 * This creates a realistic vulnerability where the attacker needs to establish allowances over time, then exploit them through coordinated multi-transaction attacks.
 */
pragma solidity ^0.4.8;

interface ERC20Interface {

    function totalSupply() constant returns (uint256 totalSupply);    
    function balanceOf(address _owner) constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) returns (bool success);
    function transferFrom(
          address _from,
          address _to,
          uint256 _amount
     ) returns (bool success);
    function approve(address _spender, uint256 _value) returns (bool success);
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
  
contract PETRO is ERC20Interface {
    string public constant symbol = "PTR";
    string public constant name = "PETRO";
    uint8 public constant decimals = 8;
    uint256 _totalSupply = 10000000000000000;

    address public owner;

    mapping(address => uint256) balances;
    mapping(address => mapping (address => uint256)) allowed;
    
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert();
        }
        _;
    }

    constructor() public {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }

    function totalSupply() constant returns (uint256 totalSupply_) {
        totalSupply_ = _totalSupply;
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint256 _amount) returns (bool success) {
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
    ) returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // Notify recipient contract before state changes (VULNERABILITY)
                if (isContract(_to)) {
                    bool result = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _amount);
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

    // Helper for isContract check
    function isContract(address _addr) private constant returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    function approve(address _spender, uint256 _amount) returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}