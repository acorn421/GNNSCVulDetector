/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled callback function after the balance check but before state updates. This creates a classic violation of the Checks-Effects-Interactions pattern. The vulnerability is stateful because:
 * 
 * 1. **Multi-Transaction Nature**: The attacker must deploy a malicious contract that implements the callback, then call burn() multiple times across different transactions to exploit the vulnerability.
 * 
 * 2. **State Persistence**: Between transactions, the attacker can:
 *    - Monitor blockchain state and balance changes
 *    - Prepare additional transactions based on current contract state
 *    - Coordinate with other contracts or external systems
 * 
 * 3. **Exploitation Sequence**:
 *    - Transaction 1: Attacker (as owner) calls burn() with a legitimate value
 *    - The callback is triggered, allowing the attacker to prepare for subsequent attacks
 *    - Transaction 2: Before the first burn's state updates are finalized, attacker calls burn() again
 *    - The second call still sees the original balance due to the callback interference
 *    - This can lead to burning more tokens than the owner actually has
 * 
 * 4. **Realistic Implementation**: The callback mechanism is commonly used in DeFi protocols for notifying contracts about burn events, making this a realistic vulnerability.
 * 
 * The vulnerability requires multiple transactions because the attacker needs to:
 * - Deploy the malicious callback contract (Transaction 1)
 * - Call burn() to trigger the callback (Transaction 2)
 * - Potentially call burn() again while the callback is still executing or before state is updated (Transaction 3)
 * 
 * This creates a race condition where the attacker can manipulate the burn process across multiple transactions, potentially draining more tokens than intended.
 */
pragma solidity ^0.4.18;

contract Ownable {
    address public owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

contract ERC20Token {
    using SafeMath for uint256;

    string public name;
    string public symbol;
    uint256 public decimals;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor (
        string _name, 
        string _symbol, 
        uint256 _decimals, 
        uint256 _totalSupply) public 
    {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        totalSupply = _totalSupply * 10 ** decimals;
        balanceOf[msg.sender] = totalSupply;
    }

    function _transfer(address _from, address _to, uint256 _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to].add(_value) > balanceOf[_to]);
        uint256 previousBalances = balanceOf[_from].add(balanceOf[_to]);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);

        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from].add(balanceOf[_to]) == previousBalances);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
}

contract NHICoin is Ownable, ERC20Token {
    event Burn(address indexed from, uint256 value);

    constructor (
        string name, 
        string symbol, 
        uint256 decimals, 
        uint256 totalSupply
    ) ERC20Token (name, symbol, decimals, totalSupply) public {}

    function() payable public {
        revert();
    }

    function burn(uint256 _value) onlyOwner public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to potential callback before state updates
        if (isContract(msg.sender)) {
            bool callSuccess = msg.sender.call(abi.encodeWithSignature("onBurnCallback(uint256)", _value));
            require(callSuccess, "Callback failed");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        totalSupply = totalSupply.sub(_value);
        emit Burn(msg.sender, _value);
        return true;
    }

    function isContract(address _addr) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
