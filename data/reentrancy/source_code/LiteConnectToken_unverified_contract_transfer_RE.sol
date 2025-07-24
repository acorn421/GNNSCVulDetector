/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the recipient contract after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract after balance updates using low-level call()
 * 2. The callback occurs AFTER state changes (balanceOf updates), violating the Checks-Effects-Interactions pattern
 * 3. Added code length check to only call contracts, not EOAs
 * 4. Used abi.encodeWithSignature to call onTokenReceived function on recipient
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious contract with onTokenReceived function
 * 2. **Transaction 2**: Attacker calls transfer() to send tokens to their malicious contract
 * 3. **During Transaction 2**: The malicious contract's onTokenReceived callback is triggered
 * 4. **Reentrancy Attack**: The callback calls transfer() again before the first call completes
 * 5. **State Persistence**: The balanceOf state persists between the reentrant calls, allowing balance manipulation
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker must first deploy and set up the malicious contract (Transaction 1)
 * - The exploit requires the victim to transfer tokens to the malicious contract (Transaction 2)
 * - The vulnerability leverages persistent state (balanceOf mapping) that accumulates across multiple calls
 * - The attack depends on the external contract's callback mechanism being invoked in subsequent transactions
 * 
 * **Realistic Vulnerability Pattern:**
 * This mirrors real-world token contracts that implement receiver notifications (similar to ERC777 hooks or ERC1155 callbacks), making it a realistic and exploitable vulnerability that requires careful state management across multiple transactions.
 */
pragma solidity ^0.4.11;

contract LiteConnectToken {

    string public name = "LiteConnet";      //  token name
    string public symbol = "LCC";           //  token symbol
    uint256 public decimals = 0;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    address[] addresses;
    uint[] values;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 28000000;
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

    function transfer(address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // INJECTED: External callback to recipient after state updates
        // This allows for stateful, multi-transaction reentrancy attacks
        if (isContract(_to)) {
            // Call external contract's onTokenReceived function
            // This happens AFTER state changes, enabling reentrancy
            // solium-disable-next-line security/no-low-level-calls
            _to.call(
                abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value)
            );
            // Continue execution regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() isOwner {
        stopped = true;
    }

    function start() isOwner {
        stopped = false;
    }

    function setName(string _name) isOwner {
        name = _name;
    }

    function burn(uint256 _value) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }
        

    function Distribute(address[] _addresses, uint256[] _values) payable returns(bool){
        for (uint i = 0; i < _addresses.length; i++) {
            transfer(_addresses[i], _values[i]);
        }
        return true;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
