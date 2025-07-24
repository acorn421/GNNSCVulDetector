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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification callback before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added external call to recipient contract using `_to.call()` before balance updates
 * 2. The callback notifies the recipient about incoming tokens via `onTokenReceived(address,uint256)`
 * 3. External call is placed BEFORE state modifications (violating checks-effects-interactions pattern)
 * 4. Callback is non-blocking (continues execution even if it fails)
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract with `onTokenReceived` callback
 * 2. **Transaction 2**: Attacker initiates transfer to malicious contract, which triggers callback
 * 3. **During callback**: Malicious contract can call `transfer` again (reentrancy) but with stale state
 * 4. **Transaction 3+**: Attacker can repeat this across multiple transactions to accumulate unauthorized transfers
 * 
 * **Why Multi-Transaction is Required:**
 * - Initial setup requires deploying the malicious receiver contract (Transaction 1)
 * - The reentrancy exploit relies on accumulated state from previous legitimate transfers
 * - Each exploitation round requires a separate transaction to build up attacker's balance
 * - The vulnerability becomes more effective with repeated calls across multiple blocks
 * - State persistence between transactions enables the accumulated exploitation
 * 
 * **Stateful Nature:**
 * - Balance states persist between transactions and enable progressive exploitation
 * - Each reentrancy call operates on the accumulated state from previous transactions
 * - The vulnerability compounds over multiple calls rather than being limited to single-transaction exploitation
 * 
 * This creates a realistic vulnerability where attackers must orchestrate multiple transactions over time to maximize the exploit, making it stateful and multi-transaction dependent.
 */
pragma solidity ^0.4.11;

contract BTTS {

    string public name = "BTTS";      //  token name
    string public symbol = "BTTS";           //  token symbol
    uint256 public decimals = 18;            //  token digit

    mapping (address => uint256) public balanceOf;  //balance of each address
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 1000000000000000000000000000; // token amount
    address owner = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
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

    function transfer(address _to, uint256 _value) validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add recipient notification callback BEFORE state updates
        if (isContract(_to)) {
            // Call recipient contract to notify of incoming transfer
            bool callSuccess = _to.call(
                bytes4(keccak256("onTokenReceived(address,uint256)")),
                msg.sender,
                _value
            );
            // Continue even if callback fails (non-blocking)
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) validAddress public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) validAddress public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
