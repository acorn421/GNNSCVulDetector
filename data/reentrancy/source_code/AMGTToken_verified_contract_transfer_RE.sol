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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification callback before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **First Transaction**: Attacker deploys a malicious contract that implements `onTokenReceived` callback. When this contract receives tokens, it can re-enter the transfer function or other contract functions while the sender's balance hasn't been updated yet.
 * 
 * 2. **Subsequent Transactions**: The attacker can exploit the accumulated state changes from previous transactions. During the callback, the attacker can:
 *    - Call transfer again to drain more tokens (classic reentrancy)
 *    - Manipulate allowances through approve/transferFrom
 *    - Build up state over multiple calls by partially draining funds each time
 * 
 * **Multi-Transaction Nature**: 
 * - The vulnerability requires setting up a malicious contract first
 * - Each transfer call allows partial exploitation during the callback
 * - State changes accumulate across multiple transactions
 * - The attacker needs to build up their position over several calls to maximize damage
 * 
 * **Exploitation Sequence**:
 * 1. Deploy malicious contract with onTokenReceived callback
 * 2. Get initial tokens transferred to the malicious contract
 * 3. In onTokenReceived, re-enter transfer function before original state is updated
 * 4. Repeat across multiple transactions to drain funds systematically
 * 
 * This creates a realistic vulnerability where the external call occurs before balance updates, and the stateful nature requires multiple transactions to fully exploit the accumulated state changes.
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

    constructor() public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[owner] = valueFounder;
    }

    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient before state changes (introduces reentrancy)
        if(_to.delegatecall.gas(2300)()) {
            // No-op just to avoid warning, not functional
        }
        // The real vulnerability logic is below
        if (isContract(_to)) {
            // Recipient contract notified before state changes
            if (!_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
                require(false);
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
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
        Transfer(msg.sender, 0x0, _value);
    }

    function isContract(address addr) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
