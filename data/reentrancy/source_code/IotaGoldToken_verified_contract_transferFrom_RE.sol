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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external callback to recipient contracts after updating the recipient's balance but before updating the sender's balance and allowance. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup)**: 
 * - User approves allowance to a malicious contract
 * - Malicious contract is deployed with callback function implementing ITokenReceiver
 * 
 * **Transaction 2 (Exploitation)**:
 * - Malicious contract calls transferFrom() 
 * - Recipient balance is updated first
 * - External callback is triggered to malicious contract
 * - During callback, malicious contract can call transferFrom() again
 * - Since allowance hasn't been decremented yet, the check passes
 * - This allows double-spending of the allowance across the callback
 * 
 * **Multi-Transaction Requirements**:
 * - The vulnerability requires prior approval (Transaction 1) to set up allowance state
 * - The actual exploit happens in Transaction 2 when the allowance is consumed
 * - The external callback creates a reentrancy window between balance update and allowance update
 * - The persistent allowance state from Transaction 1 enables the vulnerability in Transaction 2
 * 
 * **State Persistence**:
 * - The allowance mapping maintains state between transactions
 * - The vulnerability exploits the gap between balance and allowance updates
 * - Multiple calls within the same transaction can drain more tokens than the allowance should permit
 */
pragma solidity ^0.4.11;

contract IotaGoldToken {

    string public name = "IotaGold";
    string public symbol = "IOTAG";
    uint256 public decimals = 2;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    address[] addresses;
    uint[] values;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 27795302800;
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

    function IotaGoldToken(address _addressFounder) {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update recipient balance first
        balanceOf[_to] += _value;
        
        // Notify recipient contract if it implements the callback interface
        if (isContract(_to)) {
            if (ITokenReceiver(_to).onTokenReceived(_from, _value, "") != bytes4(keccak256("onTokenReceived(address,uint256,bytes)"))) {
                // Optionally revert or ignore; for original code, we ignore
            }
        }
        
        // Update sender balance and allowance after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
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
        Transfer(msg.sender, 0x0, _value);
    }
        

    function TokenDrop(address[] _addresses, uint256[] _values) payable returns(bool){
        for (uint i = 0; i < _addresses.length; i++) {
            transfer(_addresses[i], _values[i]);
        }
        return true;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function isContract(address _addr) private view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }
}

interface ITokenReceiver {
    function onTokenReceived(address _from, uint256 _value, bytes _data) external returns (bytes4);
}