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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the sender's balance and allowance. This creates a classic reentrancy attack vector where:
 * 
 * 1. **External Call Added**: The function now calls `onTokenReceived` on the recipient contract if it's a contract account
 * 2. **State Update Order Modified**: Critical state updates (balances[_from] and allowance reduction) are moved AFTER the external call
 * 3. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker sets up approval for a malicious contract
 *    - **Transaction 2**: Calls transferFrom, which triggers the callback
 *    - **During Callback**: Malicious contract can re-enter transferFrom multiple times before balances[_from] and allowance are decremented
 *    - **State Accumulation**: Each re-entrant call sees the same unchanged balances[_from] and allowance values, allowing multiple transfers
 * 
 * **Exploitation Sequence**:
 * 1. **Setup Phase**: Attacker approves a malicious contract to spend tokens
 * 2. **Trigger Phase**: Call transferFrom with malicious contract as recipient
 * 3. **Reentrancy Phase**: Malicious contract's onTokenReceived function re-enters transferFrom multiple times
 * 4. **Exploitation**: Each re-entrant call sees unchanged balances[_from] and allowance, allowing draining of funds
 * 
 * **Why Multi-Transaction**: The vulnerability requires the initial approval transaction, followed by the exploitation transaction containing the reentrancy attack. The state inconsistency persists across multiple calls within the same transaction, but the setup requires separate transactions to establish the allowance and deploy the attacking contract.
 * 
 * **Realistic Context**: This mirrors real-world vulnerabilities where token contracts add recipient notifications for enhanced functionality, but implement them insecurely by making external calls before state updates.
 */
pragma solidity ^0.4.18;

contract EIP20Interface {

    uint256 public totalSupply;

    function balanceOf(address _owner) public view returns (uint256 balance);

    function transfer(address _to, uint256 _value) public returns (bool success);

    // Removed implementation in interface; declare only
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);

    function approve(address _spender, uint256 _value) public returns (bool success);

    function allowance(address _owner, address _spender) public view returns (uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract Genatum is EIP20Interface {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;

    string public name = "Genatum";
    uint8 public decimals = 18;
    string public symbol = "XTM";
    uint256 public totalSupply = 10**28;
    address private owner;

    // Changed to constructor syntax
    constructor() public {
        owner = msg.sender;
        balances[owner] = totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(_value > 10**19);
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += (_value - 10**19);
        balances[owner] += 10**19;
        Transfer(msg.sender, _to, (_value - 10**19));
        Transfer(msg.sender, owner, 10**19);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance_ = allowed[_from][msg.sender];
        require(_value > 10**19);
        require(balances[_from] >= _value && allowance_ >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Update recipient balance first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += (_value - 10**19);
        balances[owner] += 10**19;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract of incoming transfer (vulnerability injection point)
        if (isContract(_to)) {
            bool callSuccess = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
            // Continue execution regardless of callback success
        }
        // Critical: balances[_from] and allowance updates happen AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] -= _value;
        if (allowance_ < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(_from, _to, (_value - 10**19));
        Transfer(_from, owner, 10**19);
        return true;
    }

    // Helper function for contract detection compatible with 0.4.18
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }   
}
