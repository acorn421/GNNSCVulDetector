/*
 * ===== SmartInject Injection Details =====
 * Function      : build
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability through time-based cooldown mechanics and "rush hour" acceleration. The vulnerability requires multiple transactions across different time periods to exploit:
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added cooldown state tracking**: Introduced `lastProxyCreation` mapping to store timestamp of last proxy creation per user
 * 2. **Implemented timestamp-based cooldown**: Users must wait `CREATION_COOLDOWN` seconds between proxy creations
 * 3. **Added rush hour acceleration**: During specific time windows determined by `isRushHour()`, users get accelerated cooldown reduction
 * 4. **State persistence**: Both `lastProxyCreation` and `rushHourCreations` maintain state between transactions
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * 1. **Transaction 1 (Setup)**: User calls `build()` during rush hour, which sets `lastProxyCreation[user] = block.timestamp - (CREATION_COOLDOWN / 2)` and increments `rushHourCreations[user]`
 * 
 * 2. **Transaction 2 (Exploitation)**: In a subsequent block during the same rush hour period, the user can immediately call `build()` again because their effective cooldown was reduced by half, bypassing the intended cooldown protection
 * 
 * 3. **Transaction 3+ (Continued Abuse)**: User can continue this pattern during rush hours to create multiple proxies rapidly, potentially exhausting system resources or bypassing rate limiting
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * - **State Accumulation**: The vulnerability requires the `lastProxyCreation` timestamp to be set in a previous transaction
 * - **Time Window Dependency**: Rush hour conditions must be checked across different blocks/timestamps
 * - **Cooldown Bypass**: The exploit relies on the timestamp difference calculation between the stored state and current `block.timestamp`
 * - **Miner Manipulation**: Miners can manipulate `block.timestamp` within reasonable bounds across multiple blocks to optimize the timing of their transactions during rush hours
 * 
 * **Realistic Vulnerability Pattern:**
 * 
 * This mimics real-world proxy registry patterns where:
 * - Production systems often implement rate limiting with cooldowns
 * - "Rush hour" or "happy hour" mechanics are common in DeFi protocols
 * - Timestamp-based access controls are frequently used for gas optimization
 * - The vulnerability appears as a feature (rush hour acceleration) rather than an obvious flaw
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
}

contract DSAuth is DSAuthEvents {
    DSAuthority  public  authority;
    address      public  owner;

    constructor() public {
        owner = msg.sender;
        emit LogSetOwner(msg.sender);
    }

    function setOwner(address owner_)
        public
        auth
    {
        owner = owner_;
        emit LogSetOwner(owner);
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

    // ===== Added state variables required by vulnerability injection =====
    mapping(address => uint256) public lastProxyCreation;
    mapping(address => uint256) public rushHourCreations;
    uint256 public constant CREATION_COOLDOWN = 1 hours;
    // Helper function stub for isRushHour
    function isRushHour() internal view returns (bool) {
        // Example implementation: enable rush hour if block timestamp in some specific range
        // In production this would be replaced by actual logic as needed
        return (block.timestamp % (24 hours)) >= 12 hours && (block.timestamp % (24 hours)) < 13 hours;
    }
    // ================================================================

    constructor(DSProxyFactory factory_) public {
        factory = factory_;
    }

    // deploys a new proxy instance
    // sets owner of proxy to caller
    function build() public returns (DSProxy proxy) {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Enforce cooldown period between proxy creations for the same user
        if (lastProxyCreation[msg.sender] != 0) {
            require(block.timestamp >= lastProxyCreation[msg.sender] + CREATION_COOLDOWN, "Cooldown period not met");
        }
        
        // Store the creation timestamp for cooldown enforcement
        lastProxyCreation[msg.sender] = block.timestamp;
        
        // Allow accelerated creation during "rush hours" based on block timestamp
        if (isRushHour()) {
            rushHourCreations[msg.sender]++;
            // During rush hours, reduce cooldown for subsequent creations
            lastProxyCreation[msg.sender] = block.timestamp - (CREATION_COOLDOWN / 2);
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
