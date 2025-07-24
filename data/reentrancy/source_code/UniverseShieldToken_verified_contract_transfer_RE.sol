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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Before State Updates**: Added an external call to `ITokenReceiver(_to).onTokenReceived()` before updating balances, violating the checks-effects-interactions pattern. This creates a reentrancy window where the external contract can call back into the token contract.
 * 
 * 2. **Stateful Tracking**: Introduced `accumulatedTransfers[msg.sender]` mapping to track transfer timestamps, creating persistent state that accumulates across multiple transactions.
 * 
 * 3. **Multi-Transaction Exploitation Path**: The vulnerability requires multiple transactions to exploit:
 *    - Transaction 1: Attacker calls transfer() to a malicious contract, which triggers the external call
 *    - During the external call, the malicious contract can call back into transfer() while the first call's state updates are pending
 *    - The accumulated transfer tracking persists between calls, allowing the attacker to build up state over multiple transactions
 *    - Subsequent transactions can exploit the inconsistent state created by the reentrancy
 * 
 * 4. **Realistic Integration**: The callback mechanism is a common pattern in token contracts for notifying recipients of incoming transfers, making this vulnerability appear legitimate and subtle.
 * 
 * The vulnerability is multi-transaction because:
 * - The accumulated transfer state builds up over time
 * - The attacker needs to establish the initial state in one transaction
 * - The actual exploitation happens in subsequent transactions when the accumulated state enables the attack
 * - The reentrancy window combined with the persistent state tracking creates opportunities for complex, multi-step exploits
 * 
 * This creates a realistic, stateful vulnerability that requires careful sequencing of multiple transactions to exploit effectively.
 */
pragma solidity ^0.4.11;

contract UniverseShieldToken {

    string public name = "Universe Shield Token";      //  token name
    string public symbol = "UST";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => uint256) public accumulatedTransfers; // <-- Added missing declaration

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 1000000000000000;
    address owner = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    function UniverseShieldToken(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        Transfer(0x0, _addressFounder, valueFounder);
    }

    // Interface ITokenReceiver must be outside any function or contract in Solidity 0.4.x,
    // so we move this outside the contract.

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add accumulated transfer tracking for multi-transaction vulnerability
        if (accumulatedTransfers[msg.sender] == 0) {
            accumulatedTransfers[msg.sender] = block.timestamp;
        }
        
        // External call before state updates - creates reentrancy window
        if (isContract(_to)) {
            // Call recipient contract to notify of incoming transfer
            // No try-catch in Solidity 0.4.x; use low-level call instead
            bytes4 sig = bytes4(keccak256("onTokenReceived(address,uint256)"));
            // ignore return value, do not throw on failure
            _to.call(sig, msg.sender, _value);
        }
        
        // State updates after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update accumulated transfer amount (stateful component)
        accumulatedTransfers[msg.sender] = block.timestamp;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);
        return true;
    }

    // Helper function to check if address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
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

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

// Define ITokenReceiver outside the contract (Solidity 0.4.x does not allow interface inside contract)
interface ITokenReceiver {
    function onTokenReceived(address _from, uint256 _value) external;
}
