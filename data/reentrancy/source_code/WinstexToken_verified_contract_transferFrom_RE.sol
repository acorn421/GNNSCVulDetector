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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding External Call**: Introduced a transfer notification callback to the recipient contract (_to) after balance updates but before allowance updates
 * 
 * 2. **Violating Checks-Effects-Interactions**: The external call occurs between the balance updates and allowance updates, creating a vulnerable window where state is inconsistent
 * 
 * 3. **Stateful Exploitation**: The vulnerability leverages persistent state across multiple transactions:
 *    - Transaction 1: User approves attacker contract for large allowance
 *    - Transaction 2: transferFrom called with malicious contract as _to
 *    - During callback: Malicious contract sees updated balances but unchanged allowance, enabling re-entrance with different parameters
 * 
 * 4. **Multi-Transaction Dependency**: The attack requires:
 *    - Setup transaction(s) to establish allowances
 *    - Main transaction triggering the vulnerable external call
 *    - Re-entrant calls exploiting the state inconsistency
 *    - The vulnerability cannot be exploited in a single atomic transaction
 * 
 * 5. **Realistic Implementation**: The transfer notification pattern is common in advanced ERC-20 implementations and appears as a legitimate feature enhancement
 * 
 * **Exploitation Scenario**:
 * - Tx1: victim.approve(attacker, 1000)
 * - Tx2: attacker.transferFrom(victim, maliciousContract, 100)
 * - During onTokenTransfer callback: maliciousContract re-enters with transferFrom(victim, attacker, 900)
 * - The re-entrant call succeeds because allowance hasn't been updated yet, but balance changes are visible
 * - Result: Attacker drains more tokens than intended allowance permits
 * 
 * The vulnerability is stateful (depends on pre-existing allowances) and multi-transaction (requires setup + exploitation phases).
 */
pragma solidity ^0.4.22;

contract WinstexToken {

    string public name = "WINSTEX";
    string public symbol = "WIN";
    uint256 public constant decimals = 18;
    address public adminWallet;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;
    uint public constant supplyNumber = 968000000;
    uint public constant powNumber = 10;
    uint public constant TOKEN_SUPPLY_TOTAL = supplyNumber * powNumber ** decimals;
    uint256 constant valueFounder = TOKEN_SUPPLY_TOTAL;
    address owner = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert(!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    constructor() public {
        owner = msg.sender;
        adminWallet = owner;
        totalSupply = valueFounder;
        balanceOf[owner] = valueFounder;
        emit Transfer(0x0, owner, valueFounder);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Update balances first (Effects)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to recipient for transfer notification BEFORE updating allowance
        if (isContract(_to)) {
            ITransferNotification(_to).onTokenTransfer(_from, _value, msg.sender);
        }
        // Update allowance AFTER external call (vulnerable window)
        allowance[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() public isOwner {
        stopped = true;
    }

    function start() public isOwner {
        stopped = false;
    }

    function setName(string _name) public isOwner {
        name = _name;
    }

    function setSymbol(string _symbol) public isOwner {
        symbol = _symbol;
    }

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // Helper function to check if _addr is a contract (for 0.4.22 compatibility)
    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}

interface ITransferNotification {
    function onTokenTransfer(address _from, uint256 _value, address _sender) external;
}
