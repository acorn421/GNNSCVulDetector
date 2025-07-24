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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after deducting from sender's balance but before adding to recipient's balance. This creates a window where the contract state is inconsistent across multiple transactions. The vulnerability requires multiple function calls to exploit effectively:
 * 
 * 1. **First Transaction**: Attacker deploys a malicious contract that implements `onTokenReceived()` to re-enter the transfer function
 * 2. **Second Transaction**: Attacker calls transfer() to their malicious contract, which triggers the external call
 * 3. **Reentrant Calls**: The malicious contract's `onTokenReceived()` function makes additional transfer calls while the original transfer is still executing
 * 4. **State Exploitation**: During reentrancy, the sender's balance has already been deducted but recipient's balance hasn't been added yet, allowing manipulation of this inconsistent state
 * 
 * The vulnerability is stateful because:
 * - Balance changes persist between transactions
 * - The inconsistent state window allows accumulated exploitation
 * - Multiple reentrant calls can drain more tokens than the sender originally had
 * - Each reentrant call operates on the modified state from previous calls
 * 
 * This cannot be exploited in a single transaction because the external call and state manipulation require the contract interaction pattern that only occurs when transferring to contract addresses, and the exploitation depends on the timing of state updates across multiple function invocations.
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

    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Deduct from sender's balance immediately
        balanceOf[msg.sender] -= _value;
        
        // Notify recipient contract if it's a contract address
        if (isContract(_to)) {
            // Note: .call and abi.encodeWithSignature exist, but .code property does not in <0.8
            // This keeps the same vulnerability intention
            bool callSuccess = _to.call(
                abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value)
            );
            require(callSuccess, "Recipient notification failed");
        }
        
        // Add to recipient's balance after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
