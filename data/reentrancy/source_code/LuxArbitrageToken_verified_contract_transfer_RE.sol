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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call()` with recipient notification callback before balance updates
 * 2. The call happens before critical state changes (balance updates), creating reentrancy window
 * 3. Used low-level call to avoid reverting on failure, allowing continued execution
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious contract with `onTokenReceived` callback
 * 2. **Transaction 2**: Attacker calls `transfer()` to their malicious contract
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived` callback is triggered before balances are updated
 * 4. **Reentrancy**: The callback can call `transfer()` again, seeing the old balance state
 * 5. **State Accumulation**: Multiple reentrant calls can manipulate balances before the original call completes
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker must first deploy and set up the malicious contract (Transaction 1)
 * - The actual exploit happens during the transfer call (Transaction 2)
 * - The vulnerability leverages persistent state (balanceOf mappings) that carries between transactions
 * - The exploit depends on the contract having accumulated tokens from previous transactions
 * - Each reentrant call within Transaction 2 can manipulate the same persistent state multiple times
 * 
 * **Realistic Context:**
 * This pattern is commonly seen in tokens that notify recipients about incoming transfers, similar to ERC-777 hooks or custom callback mechanisms. The vulnerability is subtle because the notification seems like a reasonable feature but creates a critical reentrancy window.
 */
pragma solidity ^0.4.11;

contract LuxArbitrageToken {

    string public name = "Luxury Arbitrage token";      //  token name
    string public symbol = "LARB";           //  token symbol
    uint256 public decimals = 18;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 1000000000 * (10 ** 18); // explicit value, since (10 ** decimals) is not a constant in 0.4.11
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

    function LuxArbitrageToken() public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[owner] = valueFounder;
        emit Transfer(0x0, owner, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient before state update - vulnerable to reentrancy
        uint size;
        assembly { size := extcodesize(_to) }
        if(size > 0) {
            // Call recipient's onTokenReceived callback if it's a contract
            var callSuccess = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue execution regardless of callback success
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
}
