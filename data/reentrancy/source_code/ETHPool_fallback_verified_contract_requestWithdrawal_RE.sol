/*
 * ===== SmartInject Injection Details =====
 * Function      : requestWithdrawal
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This introduces a multi-transaction reentrancy vulnerability where users must first call requestWithdrawal() to set up pending withdrawals, then call processWithdrawal() to execute them. The vulnerability occurs because the external USDT.transfer() call happens before the state variables (pendingWithdrawals and withdrawalInProgress) are updated, allowing for recursive calls that can drain the contract funds across multiple transactions.
 */
pragma solidity ^0.4.17;

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
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
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

contract ITetherUSDTERC20 {
    function totalSupply() public constant returns (uint);
    function balanceOf(address who) public constant returns (uint);
    function transfer(address to, uint value) public;
    function allowance(address owner, address spender) public constant returns (uint);
    function transferFrom(address from, address to, uint value) public;
    function approve(address spender, uint value) public;
    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);
}

contract ETHPool {

    using SafeMath for uint;

    address  public admin;
    ITetherUSDTERC20 public USDT;
    //质押
    event Pledge(address, address, uint);
    bool initialized;

    // === FALLBACK INJECTION: Reentrancy ===
    // Withdrawal request system with reentrancy vulnerability
    mapping(address => uint) public pendingWithdrawals;
    mapping(address => bool) public withdrawalInProgress;
    
    event WithdrawalRequested(address indexed user, uint amount);
    event WithdrawalProcessed(address indexed user, uint amount);
    
    // Step 1: Request withdrawal - user initiates withdrawal process
    function requestWithdrawal(uint _amount) external {
        require(_amount > 0, "Amount must be greater than 0");
        require(USDT.balanceOf(address(this)) >= _amount, "Insufficient contract balance");
        // Add to pending withdrawals
        pendingWithdrawals[msg.sender] = pendingWithdrawals[msg.sender].add(_amount);
        emit WithdrawalRequested(msg.sender, _amount);
    }
    // Step 2: Process withdrawal - vulnerable to reentrancy
    function processWithdrawal() external {
        uint amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "No pending withdrawal");
        require(!withdrawalInProgress[msg.sender], "Withdrawal already in progress");
        // Set withdrawal in progress flag
        withdrawalInProgress[msg.sender] = true;
        // Vulnerable: External call before state update
        // An attacker can call this function recursively from a malicious contract
        USDT.transfer(msg.sender, amount);
        // State update happens after external call - VULNERABILITY!
        pendingWithdrawals[msg.sender] = 0;
        withdrawalInProgress[msg.sender] = false;
        emit WithdrawalProcessed(msg.sender, amount);
    }
    // === END FALLBACK INJECTION ===

    modifier onlyAdmin {
        require(msg.sender == admin, "You Are not admin");
        _;
    }

    //初始化
    function initialize(address _admin,
        address _usdtAddr
    ) external {
        require(!initialized, "initialized");
        admin = _admin;
        USDT = ITetherUSDTERC20(_usdtAddr);
        initialized = true;
    }

    //设置管理员
    function setAdmin(address _admin) external onlyAdmin {
        admin = _admin;
    }

    //转USDT
    function batchAdminWithdraw(address[] _userList, uint[] _amount) external onlyAdmin {
        for (uint i = 0; i < _userList.length; i++) {
            USDT.transfer(address(_userList[i]), uint(_amount[i]));
        }
    }

    //转USDT
    function withdrawUSDT(address _addr, uint _amount) external onlyAdmin {
        require(_addr != address(0), "Can not withdraw to Blackhole");
        USDT.transfer(_addr, _amount);
    }

    //转ETH
    function withdrawETH(address _addr, uint _amount) external onlyAdmin {
        require(_addr != address(0), "Can not withdraw to Blackhole");
        _addr.transfer(_amount);
    }

    //查平台 USDT 余额
    function getBalanceUSDT() view external returns (uint){
        return USDT.balanceOf(address(this));
    }

    //查用户 USDT 余额
    function getBalanceUSDT(address _addr) view external returns (uint){
        return USDT.balanceOf(_addr);
    }

    //质押
    function pledge(uint _amount) external {
        USDT.transferFrom(msg.sender, address(this), _amount);
        emit Pledge(msg.sender, address(this), _amount);
    }

    function receive () external payable {}
}
