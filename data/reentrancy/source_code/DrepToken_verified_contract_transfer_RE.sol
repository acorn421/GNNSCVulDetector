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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a call to `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))` after the validation checks but before the balance modifications
 * 2. **Violation of Checks-Effects-Interactions Pattern**: The external call now occurs between the checks and the effects, creating a reentrancy window
 * 3. **Realistic Business Logic**: The external call simulates a token transfer notification mechanism (similar to ERC777 hooks), which is a legitimate feature that could realistically be added to a token contract
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys a malicious contract that implements `onTokenReceived(address,uint256)`
 * - The malicious contract's `onTokenReceived` function calls back to `transfer()` with different parameters
 * - Initial transfer passes all validation checks
 * - During the external call, the malicious contract re-enters `transfer()` before the original state updates complete
 * - The reentrancy occurs in the same transaction, but the exploit accumulates state inconsistencies
 * 
 * **Transaction 2+ - Exploitation Phase:**
 * - Attacker repeats the process with carefully crafted amounts
 * - Each transaction builds upon the state inconsistencies created in previous transactions
 * - The accumulated effect allows the attacker to drain more tokens than they should be able to
 * 
 * **Why Multi-Transaction Exploitation:**
 * 
 * 1. **State Persistence**: The `balanceOf` mappings persist between transactions, allowing accumulated exploitation effects
 * 2. **Incremental Exploitation**: Each reentrancy attack creates small inconsistencies that compound over multiple transactions
 * 3. **Gas Limits**: A single transaction has gas limits that prevent infinite reentrancy; multiple transactions overcome this limitation
 * 4. **Detection Evasion**: Spreading the attack across multiple transactions makes it harder to detect and appears more like normal usage
 * 
 * **Realistic Exploitation Example:**
 * - Attacker has 100 tokens
 * - Transaction 1: Transfer 50 tokens to malicious contract, during notification the contract re-enters and transfers another 50 tokens before the first state update completes
 * - Transaction 2: Repeat the process, exploiting the accumulated state inconsistencies
 * - Over multiple transactions, the attacker can extract more tokens than their original balance
 * 
 * **Technical Details:**
 * - The vulnerability requires the recipient to be a contract (checked via `_to.code.length > 0`)
 * - The external call happens after validation but before state updates, creating the classic reentrancy window
 * - The `(bool callSuccess,) = _to.call(...)` pattern ignores the return value, making it seem like a defensive programming practice while actually enabling the attack
 * - Each transaction's reentrancy creates persistent state changes that enable further exploitation in subsequent transactions
 */
pragma solidity ^0.4.18;

contract DrepToken {

    string public name = "DREP";
    string public symbol = "DREP";
    uint8 public decimals = 18;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply;
    uint256 constant initialSupply = 10000000000;
    
    bool public stopped = false;

    address internal owner = 0x0;

    modifier ownerOnly {
        require(owner == msg.sender);
        _;
    }

    modifier isRunning {
        require(!stopped);
        _;
    }

    modifier validAddress {
        require(msg.sender != 0x0);
        _;
    }

    constructor() public {
        owner = msg.sender;
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[owner] = totalSupply;
    }

    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(_to != 0x0);
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call for transfer notification before state updates
        // This creates a reentrancy window where state can be manipulated
        if (isContract(_to)) {
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue execution regardless of call result for compatibility
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        allowance[_from][msg.sender] -= _value;
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() ownerOnly public {
        stopped = true;
    }

    function start() ownerOnly public {
        stopped = false;
    }

    function burn(uint256 _value) isRunning validAddress public {
        require(balanceOf[msg.sender] >= _value);
        require(totalSupply >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
    }

    function isContract(address _addr) internal view returns (bool is_contract) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
