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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify recipient contracts before updating balances. This creates a classic reentrancy vulnerability where:
 * 
 * 1. **Multi-Transaction Setup Required**: The attacker must first deploy a malicious contract and fund their account in separate transactions before the exploit can begin.
 * 
 * 2. **Stateful Exploitation**: The vulnerability exploits the persistent state of balanceOf mappings across multiple transactions. Each reentrant call sees the unchanged sender balance, allowing multiple withdrawals.
 * 
 * 3. **External Call Before State Update**: The call to _to.call() occurs before balanceOf is updated, creating the reentrancy window where state is inconsistent.
 * 
 * 4. **Realistic Integration**: The onTokenReceived callback pattern is common in modern token standards (ERC777, ERC1363) making this vulnerability realistic and subtle.
 * 
 * **Multi-Transaction Exploitation Sequence**:
 * - Transaction 1: Attacker deploys malicious contract with onTokenReceived implementation
 * - Transaction 2: Attacker funds their account with tokens
 * - Transaction 3: Attacker calls transfer() to malicious contract, triggering reentrancy chain
 * - During Transaction 3: Malicious contract's onTokenReceived calls back into transfer() multiple times before original state update completes
 * 
 * The vulnerability requires this multi-transaction sequence and depends on accumulated state changes (account balance, contract deployment) making it impossible to exploit in a single atomic transaction.
 */
pragma solidity ^0.4.11;

contract Bithemoth {

    string public name = "Bithemoth";      //  token name
    string public symbol = "BHM";           //  token symbol
    uint256 public decimals = 18;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 200000000000000000000000000;
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

    function Bithemoth(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        emit Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient before state update (creates reentrancy vulnerability)
        if(isContract(_to)) {
            // External call to potential contract recipient
            bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
            // Continue execution regardless of call result for compatibility
        }
        
        // State updates occur AFTER external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    function isContract(address _addr) private view returns (bool is_contract) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
