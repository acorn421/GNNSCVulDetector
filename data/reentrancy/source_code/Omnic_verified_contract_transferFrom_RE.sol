/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * **Specific Code Changes:**
 * 1. **Added External Call**: Introduced a call to `_to.call()` that attempts to notify the recipient contract about the incoming token transfer
 * 2. **Violated Checks-Effects-Interactions**: The external call is made BEFORE the allowance state is updated, creating a classic reentrancy vulnerability
 * 3. **Contract Detection**: Added `_to.code.length > 0` check to only call contracts, making the vulnerability realistic
 * 4. **Error Handling**: Added a require statement to handle call failures, maintaining function robustness
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * This vulnerability requires multiple transactions and accumulated state to exploit:
 * 
 * **Setup Phase (Transaction 1):**
 * - Victim approves attacker's contract for a certain allowance (e.g., 100 tokens)
 * - Attacker deploys a malicious contract that implements the `onTokenReceived` callback
 * 
 * **Exploitation Phase (Transactions 2-N):**
 * - **Transaction 2**: Attacker calls `transferFrom(victim, attackerContract, 50)` 
 * - **Reentrancy**: The external call triggers `attackerContract.onTokenReceived()`
 * - **State Exploitation**: Since allowance hasn't been updated yet, the attacker can call `transferFrom` again with the same allowance
 * - **Transaction 3**: Attacker recursively calls `transferFrom(victim, attackerContract, 50)` again
 * - **State Accumulation**: Each reentrant call exploits the unchanged allowance state
 * 
 * **Why Multi-Transaction Nature is Required:**
 * 1. **Allowance Setup**: The victim must first approve the attacker's allowance in a separate transaction
 * 2. **State Persistence**: The allowance mapping persists between transactions, enabling the exploit
 * 3. **Callback Mechanism**: The external call provides the reentrancy window that persists across the transaction boundary
 * 4. **Accumulated Damage**: Multiple reentrant calls can drain more tokens than the original allowance permitted
 * 
 * **Realistic Attack Scenario:**
 * An attacker could drain 500 tokens from a victim who only approved 100 tokens by:
 * 1. Getting 100 token allowance from victim
 * 2. Calling transferFrom(victim, maliciousContract, 50) 
 * 3. In the callback, calling transferFrom again before allowance is updated
 * 4. Repeating this process to exceed the intended allowance limit
 * 
 * This creates a stateful vulnerability where the persistent allowance state enables multi-transaction exploitation.
 */
pragma solidity ^0.4.18;

contract Ownable {
    address public owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

contract ERC20Token {
    using SafeMath for uint256;

    string public name;
    string public symbol;
    uint256 public decimals;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor (
        string _name, 
        string _symbol, 
        uint256 _decimals, 
        uint256 _totalSupply) public 
    {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        totalSupply = _totalSupply * 10 ** decimals;
        balanceOf[msg.sender] = totalSupply;
    }

    function _transfer(address _from, address _to, uint256 _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to].add(_value) > balanceOf[_to]);
        uint256 previousBalances = balanceOf[_from].add(balanceOf[_to]);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);

        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from].add(balanceOf[_to]) == previousBalances);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract if it's a contract address
        if(isContract(_to)) {
            // External call before state update - creates reentrancy vulnerability
            require(_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value), "Token notification failed");
        }
        // State update happens AFTER external call (violates checks-effects-interactions)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
}

contract Omnic is Ownable, ERC20Token {
    event Burn(address indexed from, uint256 value);

    constructor (
        string name, 
        string symbol, 
        uint256 decimals, 
        uint256 totalSupply
    ) ERC20Token (name, symbol, decimals, totalSupply) public {}

    function() public payable {
        revert();
    }

    function burn(uint256 _value) onlyOwner public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        totalSupply = totalSupply.sub(_value);
        emit Burn(msg.sender, _value);
        return true;
    }
}
