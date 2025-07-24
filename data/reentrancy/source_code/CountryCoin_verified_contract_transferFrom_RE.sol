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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 
 * 1. **State Backup Variables**: Added variables to store original balances and allowance values for potential rollback
 * 2. **External Call Injection**: Added an external call to the recipient address (_to) using a callback mechanism (`onTokenReceived`)
 * 3. **Rollback Logic**: Implemented state rollback if the external call fails, creating inconsistent state windows
 * 4. **Code Length Check**: Added check for contract code to only call contracts, making it more realistic
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker approves a malicious contract to spend tokens on their behalf
 * - The malicious contract implements `onTokenReceived` callback
 * - State: allowance[attacker][maliciousContract] = X tokens
 * 
 * **Transaction 2 (Exploitation):**
 * - Victim calls `transferFrom(attacker, maliciousContract, amount)`
 * - Contract updates balances and allowance first
 * - External call to `maliciousContract.onTokenReceived()` is made
 * - During the callback, the malicious contract can:
 *   - Call `transferFrom` again with remaining allowance
 *   - The allowance has been decremented but callback allows re-entry
 *   - Extract more tokens than originally approved
 * 
 * **Transaction 3+ (Continuation):**
 * - The malicious contract can continue the reentrancy attack
 * - Each callback can trigger additional `transferFrom` calls
 * - State accumulates across multiple transaction contexts
 * - The attacker can drain allowances beyond intended limits
 * 
 * **Why Multi-Transaction Requirement:**
 * 
 * 1. **State Persistence**: The vulnerability leverages allowance decrements that persist between callback invocations
 * 2. **Accumulated Effect**: Each reentrant call reduces allowance but allows further exploitation in subsequent calls
 * 3. **Callback Chain**: The external calls create a chain of transactions where each callback can trigger new transfers
 * 4. **Rollback Complexity**: The rollback mechanism creates windows where state is inconsistent across transaction boundaries
 * 
 * **Real-World Relevance:**
 * This pattern mimics modern token standards (ERC-777, ERC-1155) that include callback mechanisms for transfer notifications, making it a realistic vulnerability that could appear in production code attempting to implement advanced token features.
 */
pragma solidity ^0.4.4;

contract CountryCoin {

    string public constant name = "CountryCoin";
    string public constant symbol = "CCN";
    uint public constant decimals = 8;
    uint public totalSupply;

    mapping (address => uint) balances;
    mapping (address => mapping (address => uint)) allowed;
    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);

    uint constant oneCent = 4642857142857;
    mapping (uint16 => uint) rating;
    mapping (uint16 => mapping( address => uint)) votes;
    mapping (address => uint16[]) history;

    address owner;

    constructor() public {
        totalSupply = 750000000000000000;
        balances[this] = totalSupply;
        owner = msg.sender;
    }

    function balanceOf(address _owner) public view returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        require(balances[_to] + _value > balances[_to]);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        require(allowed[_from][_to] >= _value);
        require(balances[_to] + _value > balances[_to]);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Store original values for potential rollback
        uint originalFromBalance = balances[_from];
        uint originalToBalance = balances[_to];
        uint originalAllowance = allowed[_from][_to];

        // Perform state updates first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] -= _value;
        balances[_to] += _value;
        allowed[_from][_to] -= _value;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // External call to recipient for transfer notification (vulnerability injection point)
        // This allows the recipient to call back into the contract before the transfer is fully processed
        if (isContract(_to)) {
            bool callSuccess = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // If the external call fails, we need to rollback the state changes
            // This creates a window where state is inconsistent across transactions
            if (!callSuccess) {
                balances[_from] = originalFromBalance;
                balances[_to] = originalToBalance;
                allowed[_from][_to] = originalAllowance;
                return false;
            }
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        emit Transfer(_from, _to, _value);

        return true;
    }

    // Helper function to check if an address is a contract
    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint remaining) {
        return allowed[_owner][_spender];
    }

    function () external payable {
        uint tokenAmount = msg.value*100000000 / oneCent;
        require(tokenAmount <= balances[this]);

        balances[this] -= tokenAmount;
        balances[msg.sender] += tokenAmount;
    }

    function vote(uint16 _country, uint _amount) public {
        require(balances[msg.sender] >= _amount);
        require(_country < 1000);

        if (votes[_country][msg.sender] == 0) {
            history[msg.sender].push(_country);
        }
        balances[msg.sender] -= _amount;
        rating[_country] += _amount;
        votes[_country][msg.sender] += _amount;
    }

    function reset() public {
        for(uint16 i=0; i<history[msg.sender].length; i++) {
            uint16 country = history[msg.sender][i];
            uint amount = votes[country][msg.sender];
            balances[msg.sender] += amount;
            rating[country] -= amount;
            votes[country][msg.sender] = 0;
        }
        history[msg.sender].length = 0;
    }

    function ratingOf(uint16 _country) public view returns (uint) {
        require(_country < 1000);
        return rating[_country];
    }

    function ratingList() public view returns (uint[] memory r) {
        r = new uint[](1000);
        for(uint16 i=0; i<r.length; i++) {
            r[i] = rating[i];
        }
    }

    function withdraw() public {
        require(msg.sender == owner);
        owner.transfer(address(this).balance);
    }
}