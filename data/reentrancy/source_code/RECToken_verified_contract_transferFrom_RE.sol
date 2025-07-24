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
 * Injected a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after updating the recipient's balance but before updating the sender's balance and allowance. This creates a window where the recipient can re-enter the function with an inconsistent state - they have already received tokens but the sender's balance and allowance haven't been decremented yet. The vulnerability requires multiple transactions: (1) initial approval transactions to set up allowances, (2) transferFrom call that triggers the callback, and (3) reentrant calls from the malicious recipient contract. The exploit leverages the accumulated allowance state from previous transactions and the temporary inconsistent state during the callback window.
 */
pragma solidity ^0.4.22;

contract RECToken {

    string public name = "REC";
    string public symbol = "REC";
    uint256 public constant decimals = 18;
    address public adminWallet;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;
    uint public constant supplyNumber = 255000000;
    uint public constant powNumber = 10;
    uint public constant TOKEN_SUPPLY_TOTAL = supplyNumber * powNumber ** decimals;
    uint256 constant valueFounder = TOKEN_SUPPLY_TOTAL;
    address owner = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert(!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    constructor() public {
        owner = msg.sender;
        adminWallet = owner;
        totalSupply = valueFounder;
        balanceOf[owner] = valueFounder;
        emit Transfer(0x0, owner, valueFounder);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {

        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update recipient balance first
        balanceOf[_to] += _value;
        
        // Notify recipient contract before updating sender state
        // This allows recipient to see their new balance but sender state is not yet updated
        if (isContract(_to)) {
            bytes memory data = abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value);
            // Call without checking result (maintain vulnerability and logic)
            _to.call(data);
        }
        
        // Update sender balance and allowance after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    // Helper to check for contract code size (backward compatible with 0.4.22)
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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

    function setSymbol(string _symbol) public isOwner {
        symbol = _symbol;
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
