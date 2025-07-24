/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a burn notification callback mechanism. The vulnerability works by splitting the burn operation into two phases: 1) Deducting tokens from sender's balance, 2) External callback to notify the token holder, 3) Adding tokens to the 0x0 address. This creates a window where the sender's balance is already reduced but the burn is not yet complete, allowing for reentrancy during the callback. The vulnerability is stateful because it relies on the intermediate state where tokens are deducted but not yet moved to 0x0, and multi-transaction because it requires: (1) Initial burn call that triggers the callback, (2) Reentrant calls during the callback that can exploit the inconsistent state, (3) Additional transactions to fully exploit the accumulated state changes. An attacker contract can use the callback to make additional burn calls or transfer calls while in the intermediate state, potentially draining more tokens than they should be able to burn.
 */
pragma solidity ^0.4.11;

contract AMGTToken {

    string public name = "AmazingTokenTest";      //  token name
    string public symbol = "AMGT";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

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

    // Fixed deprecated constructor definition
    function AMGTToken() public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[owner] = valueFounder;
    }

    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Phase 1: Mark tokens for burning (stateful change)
        balanceOf[msg.sender] -= _value;
        // External call to notify token holder about burn before final state updates
        if (extcodesize(msg.sender) > 0) { // compatible with Solidity 0.4.x
            // This creates a callback opportunity before burn completion
            if (!msg.sender.call(bytes4(keccak256("onTokenBurn(uint256)")), _value)) {
                // Continue regardless of callback success
            }
        }
        // Phase 2: Complete the burn by moving to 0x0 address (can be exploited if reentrant)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // Assembly helper for extcodesize in Solidity 0.4.x
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }
}
