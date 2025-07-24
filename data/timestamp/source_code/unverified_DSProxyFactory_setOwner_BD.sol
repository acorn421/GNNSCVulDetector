/*
 * ===== SmartInject Injection Details =====
 * Function      : setOwner
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 14 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a two-phase ownership transfer system with timestamp-based delay validation. The vulnerability arises from using block.timestamp for critical security timing without proper validation bounds. Miners can manipulate block timestamps within a 15-second window according to Ethereum protocol rules, allowing them to:
 * 
 * 1. **Multi-Transaction Exploitation Path:**
 *    - Transaction 1: Call setOwner(malicious_address) to set ownershipRequestTime[malicious_address] = block.timestamp
 *    - Transaction 2: Wait for the delay period, then call setOwner(malicious_address) again when block.timestamp >= ownershipRequestTime + DELAY
 *    - Between these transactions, a miner can manipulate block timestamps to reduce the actual waiting time
 * 
 * 2. **Stateful Vulnerability Characteristics:**
 *    - Requires persistent state (ownershipRequestTime mapping) between transactions
 *    - Cannot be exploited in a single transaction due to the delay requirement
 *    - The vulnerability accumulates over time and requires multiple calls to trigger
 * 
 * 3. **Timestamp Manipulation Attack:**
 *    - Miners can set block.timestamp up to 15 seconds in the future or past
 *    - By manipulating timestamps in consecutive blocks, miners can effectively reduce the 1-hour delay
 *    - This creates a time-based race condition where ownership can be transferred faster than intended
 * 
 * 4. **Real-world Impact:**
 *    - Malicious miners could gain unauthorized ownership faster than the security delay intended
 *    - Time-sensitive operations become predictable and manipulable
 *    - The delay mechanism provides false security due to timestamp dependency
 */
// proxy.sol - execute actions atomically through the proxy's identity

// Copyright (C) 2017  DappHub, LLC

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// SPDX-License-Identifier: MIT
pragma solidity ^0.4.23;

contract DSAuthority {
    function canCall(
        address src, address dst, bytes4 sig
    ) public view returns (bool);
}

contract DSAuthEvents {
    event LogSetAuthority (address indexed authority);
    event LogSetOwner     (address indexed owner);
    // Added missing event declaration
    event LogOwnershipRequested(address indexed newOwner, uint256 timestamp);
}

contract DSAuth is DSAuthEvents {
    DSAuthority  public  authority;
    address      public  owner;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    mapping(address => uint256) public ownershipRequestTime;
    uint256 public constant OWNERSHIP_TRANSFER_DELAY = 1 hours;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

    constructor() public {
        owner = msg.sender;
        emit LogSetOwner(msg.sender);
    }

    function setOwner(address owner_)
        public
        auth
    {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // First transaction: Request ownership transfer
        if (ownershipRequestTime[owner_] == 0) {
            ownershipRequestTime[owner_] = block.timestamp;
            emit LogOwnershipRequested(owner_, block.timestamp);
            return;
        }
        // Second transaction: Execute ownership transfer after delay
        require(
            block.timestamp >= ownershipRequestTime[owner_] + OWNERSHIP_TRANSFER_DELAY,
            "Ownership transfer delay not met"
        );
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        owner = owner_;
        emit LogSetOwner(owner);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Clear the request timestamp
        delete ownershipRequestTime[owner_];
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function setAuthority(DSAuthority authority_)
        public
        auth
    {
        authority = authority_;
        emit LogSetAuthority(authority);
    }

    modifier auth {
        require(isAuthorized(msg.sender, msg.sig));
        _;
    }

    function isAuthorized(address src, bytes4 sig) internal view returns (bool) {
        if (src == address(this)) {
            return true;
        } else if (src == owner) {
            return true;
        } else if (authority == DSAuthority(0)) {
            return false;
        } else {
            return authority.canCall(src, this, sig);
        }
    }
}

contract DSNote {
    event LogNote(
        bytes4   indexed  sig,
        address  indexed  guy,
        bytes32  indexed  foo,
        bytes32  indexed  bar,
        uint              wad,
        bytes             fax
    ) anonymous;

    modifier note {
        bytes32 foo;
        bytes32 bar;

        assembly {
            foo := calldataload(4)
            bar := calldataload(36)
        }

        emit LogNote(msg.sig, msg.sender, foo, bar, msg.value, msg.data);

        _;
    }
}

// DSProxy
// Allows code execution using a persistant identity This can be very
// useful to execute a sequence of atomic actions. Since the owner of
// the proxy can be changed, this allows for dynamic ownership models
// i.e. a multisig
contract DSProxy is DSAuth, DSNote {
    DSProxyCache public cache;  // global cache for contracts

    constructor(address _cacheAddr) public {
        require(setCache(_cacheAddr));
    }

    function() public payable {
    }

    // use the proxy to execute calldata _data on contract _code
    function execute(bytes _code, bytes _data)
        public
        payable
        returns (address target, bytes32 response)
    {
        target = cache.read(_code);
        if (target == 0x0) {
            // deploy contract & store its address in cache
            target = cache.write(_code);
        }

        response = execute(target, _data);
    }

    function execute(address _target, bytes _data)
        public
        auth
        note
        payable
        returns (bytes32 response)
    {
        require(_target != 0x0);

        // call contract in current context
        assembly {
            let succeeded := delegatecall(sub(gas, 5000), _target, add(_data, 0x20), mload(_data), 0, 32)
            response := mload(0)      // load delegatecall output
            switch iszero(succeeded)
            case 1 {
                // throw if delegatecall failed
                revert(0, 0)
            }
        }
    }

    //set new cache
    function setCache(address _cacheAddr)
        public
        auth
        note
        returns (bool)
    {
        require(_cacheAddr != 0x0);        // invalid cache address
        cache = DSProxyCache(_cacheAddr);  // overwrite cache
        return true;
    }
}

// DSProxyFactory
// This factory deploys new proxy instances through build()
// Deployed proxy addresses are logged
contract DSProxyFactory {
    event Created(address indexed sender, address indexed owner, address proxy, address cache);
    mapping(address=>bool) public isProxy;
    DSProxyCache public cache = new DSProxyCache();

    // deploys a new proxy instance
    // sets owner of proxy to caller
    function build() public returns (DSProxy proxy) {
        proxy = build(msg.sender);
    }

    // deploys a new proxy instance
    // sets custom owner of proxy
    function build(address owner) public returns (DSProxy proxy) {
        proxy = new DSProxy(cache);
        emit Created(msg.sender, owner, address(proxy), address(cache));
        proxy.setOwner(owner);
        isProxy[proxy] = true;
    }
}

// DSProxyCache
// This global cache stores addresses of contracts previously deployed
// by a proxy. This saves gas from repeat deployment of the same
// contracts and eliminates blockchain bloat.

// By default, all proxies deployed from the same factory store
// contracts in the same cache. The cache a proxy instance uses can be
// changed.  The cache uses the sha3 hash of a contract's bytecode to
// lookup the address
contract DSProxyCache {
    mapping(bytes32 => address) cache;

    function read(bytes _code) public view returns (address) {
        bytes32 hash = keccak256(_code);
        return cache[hash];
    }

    function write(bytes _code) public returns (address target) {
        assembly {
            target := create(0, add(_code, 0x20), mload(_code))
            switch iszero(extcodesize(target))
            case 1 {
                // throw if contract failed to deploy
                revert(0, 0)
            }
        }
        bytes32 hash = keccak256(_code);
        cache[hash] = target;
    }
}

// ProxyRegistry
// This Registry deploys new proxy instances through DSProxyFactory.build(address) and keeps a registry of owner => proxy
contract ProxyRegistry {
    mapping(address => DSProxy) public proxies;
    DSProxyFactory factory;

    constructor(DSProxyFactory factory_) public {
        factory = factory_;
    }

    // deploys a new proxy instance
    // sets owner of proxy to caller
    function build() public returns (DSProxy proxy) {
        proxy = build(msg.sender);
    }

    // deploys a new proxy instance
    // sets custom owner of proxy
    function build(address owner) public returns (DSProxy proxy) {
        require(proxies[owner] == DSProxy(0) || proxies[owner].owner() != owner); // Not allow new proxy if the user already has one and remains being the owner
        proxy = factory.build(owner);
        proxies[owner] = proxy;
    }
}
