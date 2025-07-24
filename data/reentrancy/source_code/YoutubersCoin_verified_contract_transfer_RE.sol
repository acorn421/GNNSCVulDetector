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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a notification mechanism that calls the recipient contract's `onTokenReceived` function before updating balances
 * 2. **Violated Checks-Effects-Interactions Pattern**: The external call occurs after checks but before state effects (balance updates)
 * 3. **No Reentrancy Protection**: No guards prevent reentrant calls during the external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Phase 1 - Setup Transaction:**
 * - Attacker deploys a malicious contract that implements `onTokenReceived`
 * - Attacker funds their account with initial tokens
 * - The malicious contract records the token contract address and prepares for exploitation
 * 
 * **Phase 2 - First Exploit Transaction:**
 * - Attacker calls `transfer` to send tokens to their malicious contract
 * - During `onTokenReceived` callback, the contract can call `transfer` again
 * - However, the first call's state changes (balance updates) haven't occurred yet
 * - The reentrant call sees the original balance state, allowing multiple withdrawals
 * - Each reentrant call accumulates state changes that persist between transactions
 * 
 * **Phase 3 - Subsequent Exploit Transactions:**
 * - The attacker can repeat the process across multiple transactions
 * - Each transaction builds upon the persistent balance state from previous exploits
 * - The vulnerability compounds as the attacker's balance grows while the victim's balance is repeatedly drained
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 
 * 1. **State Accumulation**: Each exploit transaction leaves the attacker with more tokens, enabling larger subsequent drains
 * 2. **Persistent Balance State**: The `balances` mapping retains changes between transactions, allowing the attacker to build up their position
 * 3. **Compound Exploitation**: Later transactions can exploit the accumulated balance state from earlier transactions
 * 4. **Cross-Transaction Reentrancy**: The vulnerability depends on the persistent contract state that builds up across multiple blockchain transactions
 * 
 * **Realistic Vulnerability Pattern:**
 * This represents a common real-world pattern where tokens notify recipients of transfers, but the implementation violates the checks-effects-interactions pattern, creating a stateful reentrancy vulnerability that requires multiple transactions to fully exploit the accumulated state changes.
 */
pragma solidity ^0.4.8;

interface ERC20Interface {
    function totalSupply() external constant returns (uint256 supply);
    function balanceOf(address _owner) external constant returns (uint256 balance);
    function transfer(address _to, uint256 _amount) external returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) external returns (bool success);
    function approve(address _spender, uint256 _value) external returns (bool success);
    function allowance(address _owner, address _spender) external constant returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract YoutubersCoin is ERC20Interface {
    string public constant symbol = "YTB";
    string public constant name = "Youtubers Coin";
    uint8 public constant decimals = 8;
    uint256 _totalSupply = 10000000000000000000;

    address public owner;

    mapping(address => uint256) balances;
    mapping(address => mapping (address => uint256)) allowed;

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert();
        }
        _;
    }

    function YoutubersCoin() public {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }

    function totalSupply() public constant returns (uint256 supply) {
        supply = _totalSupply;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    // Vulnerable reentrant transfer implementation
    function transfer(address _to, uint256 _amount) public returns (bool success) {
        if (balances[msg.sender] >= _amount 
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient before state updates (vulnerable pattern)
            if (isContract(_to)) {
                // External call to recipient contract before state changes
                _to.call(
                    abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _amount)
                );
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

    // Helper function to mimic address.code.length in old Solidity
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}
