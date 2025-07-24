/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn registry before state updates. This creates a classic violation of the Checks-Effects-Interactions pattern where:
 * 
 * 1. **Multi-Transaction Exploitation**: The vulnerability requires multiple function calls to exploit because:
 *    - The attacker must first set up a malicious burn registry contract
 *    - The attacker must call burn() to trigger the external call
 *    - During the external call, the attacker's contract must re-enter burn() again
 *    - This creates a sequence where the same balance is read twice before being updated
 * 
 * 2. **State Persistence**: The vulnerability exploits persistent state changes between transactions:
 *    - balanceOf[msg.sender] state persists between the initial call and the reentrant call
 *    - The reentrant call sees the original balance (before the first deduction)
 *    - Both calls pass the balance check but only the total balance is deducted once
 * 
 * 3. **Realistic Implementation**: The burn registry pattern is commonly used in DeFi protocols for tracking burn events, making this vulnerability realistic and subtle.
 * 
 * **Exploitation Scenario:**
 * - Transaction 1: User calls burn(1000) with 1000 tokens
 * - During notifyBurn() call, attacker's registry contract re-enters burn(1000)
 * - Second call sees original balance of 1000 (before first deduction)
 * - Both calls succeed, burning 2000 tokens but user only had 1000
 * - This allows burning more tokens than owned across multiple transaction contexts
 * 
 * The vulnerability requires the accumulated state from the initial transaction to enable the exploitation in subsequent reentrant calls, making it inherently multi-transaction dependent.
 */
/**
 *Submitted for verification at Etherscan.io on 2020-03-30
*/

pragma solidity ^0.4.22;

contract Natterix {

    string public name = "Natterix";
    string public symbol = "NRX";
    uint256 public constant decimals = 18;
    address public adminWallet;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;
    uint public constant supplyNumber = 500000000;
    uint public constant powNumber = 10;
    uint public constant TOKEN_SUPPLY_TOTAL = supplyNumber * powNumber ** decimals;
    uint256 constant valueFounder = TOKEN_SUPPLY_TOTAL;
    address owner = 0x0;
    address public burnRegistry = 0x0; // Added definition for burnRegistry

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
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
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

    // Interface definition for IBurnRegistry
    // In Solidity 0.4.x, interfaces must be defined outside of contract
}

// Interface moved outside the contract.
interface IBurnRegistry {
    function notifyBurn(address who, uint256 value) external;
}

contract Natterix_BurnHelpers is Natterix {
    // Placeholder contract if helpers/extensions are needed
}

// The burn function remains as in the original contract, already inside the main contract body.
// No changes are needed there.

// The vulnerability in Natterix.burn remains preserved.