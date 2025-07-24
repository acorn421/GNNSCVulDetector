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
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to recipient contracts after state updates but before event emission. The vulnerability exploits the admin-to-admin transfer mechanism that mints new tokens, requiring multiple transactions to accumulate state and exploit the minting capability. An attacker must first become an admin, then use a malicious contract as recipient to trigger reentrancy during admin transfers, allowing unlimited token minting across multiple transactions.
 */
pragma solidity ^0.4.24;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
    if (a == 0) {
      return 0;
    }
    c = a * b;
    assert(c / a == b);
    return c;
  }
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    return a / b;
  }
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }
  function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
    c = a + b;
    assert(c >= a);
    return c;
  }
}

contract ERC20 {
    using SafeMath for uint256;

    mapping (address => uint256) public balanceOf;
    uint256 public totalSupply;
    mapping (address => bool) public admins;
    
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require (_to != address(0) && _value > 0);
        if (admins[msg.sender] == true && admins[_to] == true) {
            balanceOf[_to] = balanceOf[_to].add(_value);
            totalSupply = totalSupply.add(_value);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient contract of admin transfer (vulnerability injection point)
            if (isContract(_to)) {
                (bool notifySuccess,) = _to.call(abi.encodeWithSignature("onAdminTransfer(address,uint256)", msg.sender, _value));
                require(notifySuccess, "Admin transfer notification failed");
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            emit Transfer(msg.sender, _to, _value);
            return true;
        }
        require (balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract of transfer (vulnerability injection point)
        if (isContract(_to)) {
            (bool notifySuccess2,) = _to.call(abi.encodeWithSignature("onTransfer(address,uint256)", msg.sender, _value));
            // Continue execution even if notification fails for regular transfers
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    function approve(address _spender, uint256 _value) public returns (bool success);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }
}

contract Leader {
    address public owner;
    mapping (address => bool) public admins;
    
    modifier onlyOwner() {
        require(owner == msg.sender);
        _;
    }

    modifier onlyAdmins() {
        require(admins[msg.sender]);
        _;
    }
    
    function setOwner (address _addr) onlyOwner() public {
        owner = _addr;
    }

    function addAdmin (address _addr) onlyOwner() public {
        admins[_addr] = true;
    }

    function removeAdmin (address _addr) onlyOwner() public {
        delete admins[_addr];
    }
}

contract FCash is ERC20, Leader {
    string public name = "FCash";
    string public symbol = "FCH";
    uint8 public decimals = 8;
    // totalSupply redeclared in ERC20; set at construction
    
    using SafeMath for uint256;
    mapping (address => mapping (address => uint256)) public allowance;

    constructor() public {
        owner = msg.sender;
        admins[msg.sender] = true;
        totalSupply = 100e16;
        balanceOf[owner] = totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require (_to != address(0) && _value > 0);
        if (admins[msg.sender] == true && admins[_to] == true) {
            balanceOf[_to] = balanceOf[_to].add(_value);
            totalSupply = totalSupply.add(_value);
            emit Transfer(msg.sender, _to, _value);
            return true;
        }
        require (balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require (_value > 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require (_to != address(0) && _value > 0);
        require (balanceOf[_from] >= _value && _value <= allowance[_from][msg.sender]);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }
}
