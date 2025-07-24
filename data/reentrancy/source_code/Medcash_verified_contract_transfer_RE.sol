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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful multi-transaction reentrancy vulnerability by adding an external call to the recipient contract's onTokenReceived hook before state updates. This creates a reentrancy window where:
 * 
 * 1. **Transaction 1**: User transfers tokens to a malicious contract
 * 2. **External call**: The malicious contract's onTokenReceived is called before balance updates
 * 3. **Reentrancy**: The malicious contract can call transfer again with the same sender balance
 * 4. **State persistence**: The original sender's balance hasn't been decremented yet
 * 5. **Multi-transaction exploitation**: The attack requires the malicious contract to be deployed first (transaction 1), then the initial transfer (transaction 2), and potential subsequent transfers during reentrancy
 * 
 * The vulnerability is stateful because:
 * - The malicious contract must be deployed and positioned as the recipient
 * - The original sender's balance state persists unchanged during the external call
 * - Multiple transfers can be executed before the first state update completes
 * - Each reentrant call sees the same unchanged balance state
 * 
 * This is multi-transaction because:
 * - Deployment of malicious contract (transaction 1)
 * - Initial transfer call that triggers the vulnerability (transaction 2)
 * - Potential additional setup transactions if the attack requires specific conditions
 * - The attack exploits the gap between external call and state update within the same transaction, but requires multiple separate transactions to set up and execute effectively
 */
pragma solidity ^0.4.17;

contract Medcash {

    string public name = "Medcash";      //  token name
    string public symbol = "MEDCASH";           //  token symbol
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 20000000000000000;
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

    constructor(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        emit Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        if(_to != address(0) && extcodesize(_to) > 0) {
            bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
            // Continue execution regardless of call result for compatibility
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() isOwner public {
        stopped = true;
    }

    function start() isOwner public {
        stopped = false;
    }

    function setName(string _name) isOwner public {
        name = _name;
    }

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // Helper function for extcodesize in Solidity 0.4.x
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }
}
